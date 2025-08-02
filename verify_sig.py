import sys

from pygost.pygost import gost34112012512, gost3410
from pygost.pygost.gost3410 import CURVES
from asn1crypto import cms, pem

def verify_signature(pdf_file, sig_file):
    with open(pdf_file, 'rb') as f:
        document_data = f.read()
    
    with open(sig_file, 'rb') as f:
        signature_data = f.read()
    
    if pem.detect(signature_data):
        _, _, signature_data = pem.unarmor(signature_data)
    
    try:
        # Декодируем CMS
        signed_data = cms.ContentInfo.load(signature_data)['content']
        
        signer_info = signed_data['signer_infos'][0]
        certificates = signed_data['certificates']
        
        if not certificates:
            print("Не найден сертификат в подписи")
            return False

        cert = certificates[0].chosen
        tbs_cert = cert['tbs_certificate']
        public_key_info = tbs_cert['subject_public_key_info']
        
        algorithm = public_key_info['algorithm']['parameters']
        curve_name = algorithm.native.get('curve')
        
        if curve_name is None:
            # использовал эту курву, т.к. только с ней нормально работает
            curve = CURVES["id-GostR3410-2001-CryptoPro-A-ParamSet"] 
        else:
            curve = CURVES.get(curve_name)
            if curve is None:
                print(f"Неизвестная кривая: {curve_name}")
                return False
        
        public_key = public_key_info['public_key'].native
        pub_key = gost3410.pub_unmarshal(public_key)
        
        # хэш по госту
        digest = gost34112012512.new(document_data).digest()
        

        signature = signer_info['signature'].native
        if gost3410.verify(pub=pub_key, digest=digest, signature=signature, curve=curve):
            print("Подпись действительна")
            
            print("Алгоритм подписи:", public_key_info['algorithm'].native)
            print("\nИнформация о сертификате:")
            print(f"Владелец: {tbs_cert['subject'].native}")
            print(f"Издатель: {tbs_cert['issuer'].native}")
            print(f"Действителен с: {tbs_cert['validity']['not_before'].native} до: {tbs_cert['validity']['not_after'].native}")
            
            return True
        else:
            print("Подпись недействительна")
            
            # Эти принты опциональны, если нужно вывести информацию о сертификате и алгоритме    
            print("Алгоритм подписи:", public_key_info['algorithm'].native)
            print("Параметры алгоритма:", public_key_info['algorithm']['parameters'].native)
            print("Открытый ключ:", public_key)
            return False
            
    except Exception as e:
        print(f"Ошибка при проверке подписи: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python3 verify_sig.py <pdf_file> <sig_file>")
        sys.exit(1)
    
    if verify_signature(sys.argv[1], sys.argv[2]):
        sys.exit(0)
    else:
        sys.exit(1)