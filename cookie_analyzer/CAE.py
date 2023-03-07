from http import cookies
import re
from urllib.parse import urlparse


class CAE:
    
    def check_third_party_cookie(self, header,url=""):
        w=list(header.split('\n'))
        
        for i in w:
            if i.startswith('Set-Cookie'):
                c=cookies.SimpleCookie(i[11:])
                if 'domain' in c and c['domain'].value != url:
                    return (True,c)
                
                    
        return (False,None)
    
    
    def check_cookie_integrity(self,cookie):
        '''this function checks the integrity of the cookie whether it is modified or not. that can be done using the cookie signature. need to be implemented according to website hashing algorithm'''
        pass
    
    
                        
    def cookie_sanitization_check(self,cookie):
        
        pass    
    
        
    
    