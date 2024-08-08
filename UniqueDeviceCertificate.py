from pyasn1.type import univ, char, namedtype, tag
from pyasn1.codec.der import encoder
from cryptography import x509
from cryptography.x509 import Extension, ObjectIdentifier, UnrecognizedExtension
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta
import os
import json
import base64
# Функция для генерации серийного номера
def generate_serial_number():
    return int.from_bytes(os.urandom(7), byteorder="big") >> 17
#######################################################################################################################
#
class Cert11(univ.SequenceOf):
    componentType = univ.Any()
# Определение приватного типа данных
class MyPrivateType(univ.Sequence):
    def __init__(self, **kwargs):
        univ.Sequence.__init__(self, **kwargs)
# Определение приватных классов
class Private1112494660(MyPrivateType):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassPrivate, tag.tagFormatConstructed, 1112494660))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('BORD', char.IA5String()),
        namedtype.NamedType('INTEGER', univ.Integer())
    )
class Private1128810832(MyPrivateType):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassPrivate, tag.tagFormatConstructed, 1128810832))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('CHIP', char.IA5String()),
        namedtype.NamedType('INTEGER', univ.Integer())
    )
class Private1162037572(MyPrivateType):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassPrivate, tag.tagFormatConstructed, 1162037572))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ECID', char.IA5String()),
        namedtype.NamedType('INTEGER', univ.Integer())
    )
class Private1651335523(MyPrivateType):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassPrivate, tag.tagFormatConstructed, 1651335523))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bmac', char.IA5String()),
        namedtype.NamedType('OCTET_STRING', univ.OctetString())
    )
class Private1768777065(MyPrivateType):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassPrivate, tag.tagFormatConstructed, 1768777065))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('imei', char.IA5String()),
        namedtype.NamedType('OCTET_STRING', univ.OctetString())
    )
class Private1936879213(MyPrivateType):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassPrivate, tag.tagFormatConstructed, 1936879213))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('srnm', char.IA5String()),
        namedtype.NamedType('OCTET_STRING', univ.OctetString())
    )
class Private1969514852(MyPrivateType):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassPrivate, tag.tagFormatConstructed, 1969514852))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('udid', char.IA5String()),
        namedtype.NamedType('OCTET_STRING', univ.OctetString())
    )
class Private2003657059(MyPrivateType):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassPrivate, tag.tagFormatConstructed, 2003657059))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('wmac', char.IA5String()),
        namedtype.NamedType('OCTET_STRING', univ.OctetString())
    )
class Private1936025956(MyPrivateType):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassPrivate, tag.tagFormatConstructed, 1936025956))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('seid', char.IA5String()),
        namedtype.NamedType('OCTET_STRING', univ.OctetString())
    )
# Изменение определения класса Private1296125520
class MyPrivateType(univ.Sequence):
    pass
class Private1296125520(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('sequence', univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('MANP', char.IA5String()),
                namedtype.NamedType('SET', univ.Set())
         
                        
             )
         ))
    )
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassPrivate, tag.tagFormatConstructed, 1296125520))
class Private1329744464(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('sequence', univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('OBJP', char.IA5String()),
                namedtype.NamedType('SET', univ.Set())
         
                        
             )
         ))
    )
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassPrivate, tag.tagFormatConstructed, 1329744464))
# Определение расширения 15
class Extension15(univ.Set):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('private1296125520', Private1296125520()),
        namedtype.NamedType('private1329744464', Private1329744464())
    )
# Определение приватного расширения 1.2.840.113635.100.10.2
class PrivateExtension10_2(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('integerValue', univ.Integer(0))
    )
# Изменение определения класса 1.2.840.113635.100.8.7
class Private1400(univ.Sequence):
    pass
# Определение приватных тегов [1400] и [1403]Определение приватного расширения 1.2.840.113635.100.8.7
class Private1400(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1400))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('OCTET_STRING', univ.OctetString())
    )
class Private1403(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1403))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('OCTET_STRING', univ.OctetString())
    )	
class Extension4(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('[1400]', univ.OctetString()),
        namedtype.NamedType('[1403]', univ.OctetString())
    )		
#######################################################################################################################
private_data1 = Private1112494660()
private_data1['BORD'] = 'BORD'
private_data1['INTEGER'] = 12
private_data2 = Private1128810832()
private_data2['CHIP'] = 'CHIP'
private_data2['INTEGER'] = 32789
private_data3 = Private1162037572()
private_data3['ECID'] = 'ECID'
private_data3['INTEGER'] = 2860251324874798
private_data4 = Private1651335523()
private_data4['bmac'] = 'bmac'
private_data4['OCTET_STRING'] = '40:88:ad:50:d1:c9'
private_data5 = Private1768777065()
private_data5['imei'] = 'imei'
private_data5['OCTET_STRING'] = '35676767676767'
private_data6 = Private1936879213()
private_data6['srnm'] = 'srnm'
private_data6['OCTET_STRING'] = 'F2L5G9NZJLV6'
private_data7 = Private1969514852()
private_data7['udid'] = 'udid'
private_data7['OCTET_STRING'] = '767677677878788787888788878788788787878b'
private_data8 = Private2003657059()
private_data8['wmac'] = 'wmac'
private_data8['OCTET_STRING'] = '40:88:ad:50:d1:c9'
private_data9 = Private1936025956()
private_data9['seid'] = 'seid'
private_data9['OCTET_STRING'] = '041019E354426767667666776776767670942330279BECB1C9ABDA68'
#######################################################################################################################
# Создание объектов для приватных типов данных
private1296125520_data = Private1296125520()
private1296125520_data['sequence']['MANP'] = 'MANP'
# Здесь нужно добавить данные для 'SET' в зависимости от вашего конкретного случая
private1329744464_data = Private1329744464()
private1329744464_data['sequence']['OBJP'] = 'OBJP'
# 
extension10_2_data = PrivateExtension10_2()
# Создание объектов для приватных тегов [1400] и [1403]
private1400_data = Private1400()
private1400_data['OCTET_STRING'] = univ.OctetString('16.6')
# 
private1403_data = Private1403()
private1403_data['OCTET_STRING'] = univ.OctetString('20G75')
# Создание объекта для расширения 1.2.840.113635.100.8.7
extension4_data = Extension4()
extension4_data['[1400]'] = univ.OctetString('16.6').subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1400))
extension4_data['[1403]'] = univ.OctetString('20G75').subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1403))
# Создание сертификата
extension1_data = Cert11()
extension1_data.extend([private_data1, private_data2, private_data3, private_data4, private_data5, private_data6, private_data7, private_data8, private_data9])
# Создание объекта для расширения 15
extension15_data = Extension15()
extension15_data['private1296125520'] = private1296125520_data
extension15_data['private1329744464'] = private1329744464_data
# Сериализация данных
my_data_example1 = encoder.encode(extension1_data)
my_data_example2 = encoder.encode(extension15_data)
my_data_example3 = encoder.encode(extension10_2_data)
my_data_example4 = encoder.encode(extension4_data)
# Вывод шестнадцатеричного представления
#print(encoded_data.hex())
#######################################################################################################################
extension1 = UnrecognizedExtension(
            oid=ObjectIdentifier('1.2.840.113635.100.10.1'),# Указываем OID и сериализованное значение
            value=my_data_example1  
)
extension2 = UnrecognizedExtension(
            oid=ObjectIdentifier('1.2.840.113635.100.6.1.15'),
            value=my_data_example2
)
extension3 = UnrecognizedExtension(
            oid=ObjectIdentifier('1.2.840.113635.100.10.2'),
            value=my_data_example3
)
extension4 = UnrecognizedExtension(
            oid=ObjectIdentifier('1.2.840.113635.100.8.7'),
            value=my_data_example4
)
# Создание сертификата
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

builder = (
    x509.CertificateBuilder()
    .issuer_name(
        x509.Name([
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, "Apple Inc."),
            x509.NameAttribute(x509.OID_ORGANIZATIONAL_UNIT_NAME, "FDRDC-UCRT-SUBCA"),
        ])
    )
    .subject_name(
        x509.Name([
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, "Apple Inc."),
            x509.NameAttribute(x509.OID_ORGANIZATIONAL_UNIT_NAME, "FDRDC-UCRT-SUBCA"),
            x509.NameAttribute(x509.OID_COMMON_NAME, "00008015-000A29622830002E"),
        ])
    )
    .serial_number(generate_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .public_key(public_key)
    # Расширения
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(extension1, critical=False)
	.add_extension(extension2, critical=False)
	.add_extension(extension3, critical=False)
	.add_extension(extension4, critical=False)
)

# Подпись сертификата
certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())
# Сохраняем сертификат в файл
with open("certificate.pem", "wb") as f:
    f.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Загрузка сертификата для верификации подписи
cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
loaded_cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())


# Верификация подписи
try:
    loaded_cert.public_key().verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        ec.ECDSA(certificate.signature_hash_algorithm),
    )
    print("Подпись верна.")
except:
    print("Ошибка верификации подписи.")
# Конвертация tbs_certificate_bytes в Base64
tbs_certificate_base64 = base64.b64encode(certificate.tbs_certificate_bytes)

# Запись в файл
with open("tbs_certificate_bytes_base64.txt", "wb") as f:
    f.write(tbs_certificate_base64)
