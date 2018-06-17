#!/usr/bin/env python2
# coding: utf-8
import datetime
import hashlib
import json
import logging
import uuid
import scoring
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from optparse import OptionParser

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}

LOGGER = logging.getLogger(__name__)


class AutoNameDescriptor(object):
    """
    Дескриптор автоименованных полей
    """
    __counter = 0

    def __init__(self):
        cls = self.__class__
        prefix = cls.__name__
        index = cls.__counter
        self.field_name = '_{}#{}'.format(prefix, index)
        cls.__counter += 1

    def __get__(self, instance, owner):
        """Получение значения"""
        if instance is None:
            return self
        else:
            return getattr(instance, self.field_name)

    def __set__(self, instance, value):
        """Установка значения"""
        setattr(instance, self.field_name, value)


class BaseField(object):
    """
    Базовый класс для полей
    """
    required = AutoNameDescriptor()
    """
    Обязательное или опциональное поле
    
    True - обязательное поле\r\n
    False - опциональное поле
    
    :type: bool
    """
    nullable = AutoNameDescriptor()
    """
    Допустимость пустого значения для поля
    
    True - может быть пустым\r\n
    False - не может быть пустым
    
    :type: bool    
    """
    value = AutoNameDescriptor()
    """
    Значение записываемое в поле
    
    :type: type
    """

    def __init__(self, required=True, nullable=False):
        """
        Создаёт новый экземпляр базового поля

        :param bool required: обязательное. По умлочанию: True
        :param bool blank: может быть пустым. По умлочанию: False
        """
        self.required = required
        self.nullable = nullable
        self.value = None
        self.validate_errors = list()

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return '{} ({!r}, {!r})'.format(self.__class__.__name__, self.required, self.value)

    def __cmp__(self, other):
        if isinstance(other, BaseField):
            return cmp(self.value, other.value)

        elif isinstance(other, basestring):
            return cmp(str(self.value), other)

    def __add__(self, other):
        if isinstance(other, BaseField):
            return self.value + other.value
        elif isinstance(other, basestring):
            return str(self.value) + other

    def validate(self):
        """Проверка значения поля"""
        if self.value is None:
            if self.required:
                self.validate_errors.append(
                    (self.__class__.__name__,
                     "{}. Не определено значение обязательного поля".format(self.__class__.__name__))
                )
        elif not bool(self.value) and not self.nullable:
            self.validate_errors.append(
                (self.__class__.__name__,
                 "Значение поля {} не может быть пустым.".format(self.__class__.__name__))
            )
        return not bool(len(self.validate_errors))


class CharField(BaseField):

    def validate(self):
        super(CharField, self).validate()
        if self.value and not isinstance(self.value, basestring):
            self.validate_errors.append(
                (self.__class__.__name__,
                 "Значение поля {} должно быть типом basestring".format(self.__class__.__name__,
                                                                        self.value))
            )

        return not bool(len(self.validate_errors))


class ArgumentsField(BaseField):

    def validate(self):
        super(ArgumentsField, self).validate()
        if not isinstance(self.value, dict):
            self.validate_errors.append(
                (self.__class__.__name__,
                 "Значение поля {} должно быть типом DICT. {}".format(self.__class__.__name__,
                                                                      self.value.__class__.__name__))
            )
        return not bool(len(self.validate_errors))


class EmailField(CharField):

    def validate(self):
        super(EmailField, self).validate()
        if "@" not in self.value:
            self.validate_errors.append(
                (self.__class__.__name__,
                 "Значение поля {} должно содержать символ '@'. {}".format(self.__class__.__name__, self.value))
            )
        return not bool(len(self.validate_errors))


class PhoneField(CharField):

    def validate(self):
        super(PhoneField, self).validate()
        if len(self.value) != 11:
            self.validate_errors.append(
                (self.__class__.__name__,
                 "Значение поля {} должно быть длиной 11 символов. {}".format(self.__class__.__name__, self.value))
            )
        if self.value[0] != "7":
            self.validate_errors.append(
                (self.__class__.__name__,
                 "Значение поля {} должно начинаться с '7'. {}".format(self.__class__.__name__, self.value))
            )
        return not bool(len(self.validate_errors))


class DateField(BaseField):

    def validate(self):
        super(DateField, self).validate()
        if self.as_date() is None:
            self.validate_errors.append(
                (self.__class__.__name__,
                 "{}. Неверный формат значения даты. Допустимый формат: DD.MM.YYYY".format(self.__class__.__name__,
                                                                                           self.value))
            )
        return not bool(len(self.validate_errors))

    def as_date(self):
        try:
            return datetime.datetime.strptime(self.value, "%d.%m.%Y")
        except Exception as e:
            logging.exception(str(e))
            return None

    def __str__(self):
        return self.value


class BirthDayField(DateField):

    def validate(self):
        super(BirthDayField, self).validate()
        birtday = self.as_date()
        if birtday is not None:
            if datetime.datetime.now().year - birtday.year >= 70:
                self.validate_errors.append(
                    (self.__class__.__name__,
                     "День рождения должен быть не ранее {} года. {}".format(datetime.datetime.now().year - 70,
                                                                             birtday.year))
                )
        return not bool(len(self.validate_errors))


class GenderField(BaseField):

    def validate(self):
        super(GenderField, self).validate()

        if not isinstance(self.value, (basestring, int)):
            self.validate_errors.append(
                (self.__class__.__name__,
                 "{}. Недопустимый тип значения поляе. Допустимые типы: basestring, int".format(self.__class__.__name__)
                 )
            )
        else:
            # Перевод строкового представления в числовое (если это возможно)
            if isinstance(self.value, basestring):
                if self.value.isdigit():
                    self.value = int(self.value)
                elif self.value.lower() in GENDERS.values():
                    for k, v in GENDERS.items():
                        if self.value.lower() == v:
                            self.value = k
                            break
                else:
                    self.validate_errors.append(
                        (self.__class__.__name__,
                         "{}. Недопустимое строковое значение. Допустимые значения: {}".format(self.__class__.__name__,
                                                                                               GENDERS.values())
                         )
                    )
            # Проверка переданных числовых значений после
            if isinstance(self.value, int):
                if self.value not in (UNKNOWN, MALE, FEMALE):
                    self.validate_errors.append(
                        (self.__class__.__name__,
                         "{}. Недопустимое численное значение. Допустимые значения {}".format(self.__class__.__name__,
                                                                                              (UNKNOWN, MALE, FEMALE))
                         )
                    )
        return not bool(len(self.validate_errors))


class ClientIDsField(BaseField):

    def validate(self):
        super(ClientIDsField, self).validate()
        if not isinstance(self.value, list):
            self.validate_errors.append(
                (self.__class__.__name__,
                 "Значение поля {} должно быть типом datetime.Date. {}".format(self.__class__.__name__,
                                                                               self.value.__class__.__name__))
            )
        if not all([isinstance(el, int) for el in self.value]):
            self.validate_errors.append(
                (self.__class__.__name__,
                 "Все элементы значения поля {} должны быть INT".format(self.__class__))
            )
        return not bool(len(self.validate_errors))


class BaseRequest(object):

    def __init__(self):
        self._not_empty_field = []

    def validate_request(self):
        """
        Проверка на валидность значений в полях объекта

        :return: корректность введенных данных
        :rtype: tuple[bool, list]
        """
        errors = []
        fields = [getattr(self, field_name) for field_name in dir(self) if not (field_name.startswith('_') or callable(getattr(self, field_name)))]
        for field in fields:
            if field.value:
                self._not_empty_field.append(field.__class__.__name__)
            if not field.validate():
                errors += field.validate_errors

        return len(errors) == 0, errors

    def get_not_empty_fields(self):
        return self._not_empty_field


class ClientsInterestsRequest(BaseRequest):
    """
    Запрос интересов клиентов по их идентификаторам
    :param kwargs:
    """

    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self, **kwargs):
        """
        Создание нового экземпляра запроса

        :param kwargs:
        """
        super(ClientsInterestsRequest, self).__init__()
        self.client_ids.value = kwargs.get('client_ids', None)
        self.date.value = kwargs.get('date', None)


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, **kwargs):
        super(OnlineScoreRequest, self).__init__()
        self.first_name.value = kwargs.get('first_name', None)
        self.last_name.value = kwargs.get('last_name', None)
        self.email.value = kwargs.get('email', None)
        self.phone.value = kwargs.get('phone', None)
        self.birthday.value = kwargs.get('birthday', None)
        self.gender.value = kwargs.get('gender', None)

    def validate_request(self):
        valid, errors = super(OnlineScoreRequest, self).validate_request()
        valid = (valid and
                 ((bool(self.first_name.value) and bool(self.last_name.value)) or
                  (bool(self.phone.value) and bool(self.email.value)) or
                  (bool(self.gender.value) and bool(self.birthday.value))
                  )
                 )
        if not valid:
            errors.append(
                (self.__class__.__name__,
                 "Не найдено не одной обязательной пары: phone-email, first_name-last_name, gender-birthday")
            )
        return valid, errors


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, **kwargs):
        super(MethodRequest, self).__init__()
        self.account.value = kwargs.get('account', None)
        self.login.value = kwargs.get('login', None)
        self.token.value = kwargs.get('token', None)
        self.arguments.value = kwargs.get('arguments', None)
        self.method.value = kwargs.get('method', None)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.login == ADMIN_LOGIN:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


def online_score_method(arguments, is_admin, context, store):
    """
    Метод 'online_score'

    :param ArgumentsField arguments: аргументы вызываемеого метода
    :param bool is_admin: является ли пользователь администратором
    :param dict context: словарь контекста
    :param store: хранилище
    :return: число
    :rtype: int
    """
    request = OnlineScoreRequest(**arguments.value)
    valid, errors = request.validate_request()

    if not valid:
        return INVALID_REQUEST, '\n'.join(errors)

    context.setdefault('has', request.get_not_empty_fields())

    if is_admin:
        return OK, {"score": ADMIN_SALT}
    else:
        return OK, {"score": scoring.get_score(store=store,
                                               phone=request.phone.value,
                                               email=request.email.value,
                                               birthday=request.birthday.value,
                                               gender=request.gender.value,
                                               first_name=request.first_name.value,
                                               last_name=request.last_name.value
                                               )
                    }


def clients_interests(arguments, is_admin, context, store):
    request = ClientsInterestsRequest(**arguments.value)
    valid, errors = request.validate_request()
    if not valid:
        return INVALID_REQUEST, '\n'.join(errors)

    context.setdefault("nclients", len(request.client_ids.value))
    return OK, {cid: scoring.get_interests(store=store, cid=cid) for cid in request.client_ids.value}


METHODS = dict(
    online_score=online_score_method,
    clients_interests=clients_interests
)


def method_handler(request, ctx, store):
    method_request = MethodRequest(**request["body"])

    if not check_auth(method_request):
        return ERRORS[FORBIDDEN], FORBIDDEN

    if method_request.method.value and method_request.method.value not in METHODS.keys():
        return ERRORS[NOT_FOUND], NOT_FOUND

    code, response = METHODS[method_request.method.value](method_request.arguments, method_request.is_admin, ctx, store)
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception, e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
