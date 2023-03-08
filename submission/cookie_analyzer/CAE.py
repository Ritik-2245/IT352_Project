from http import cookies
import re
from urllib.parse import urlparse
import base64


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
    
    
                        
    

    def is_xss_in_cookie(cookie_value):
        # Check for script tags
        if re.search(r'<\s*script\s*>', cookie_value, re.IGNORECASE):
            return True

        # Check for onerror event
        if re.search(r'onerror\s*=', cookie_value, re.IGNORECASE):
            return True

        # Check for onmouseover event
        if re.search(r'onmouseover\s*=', cookie_value, re.IGNORECASE):
            return True

        # Check for javascript protocol
        if re.search(r'javascript\s*:', cookie_value, re.IGNORECASE):
            return True

        # Check for onload event
        if re.search(r'onload\s*=', cookie_value, re.IGNORECASE):
            return True

        # Check for onclick event
        if re.search(r'onclick\s*=', cookie_value, re.IGNORECASE):
            return True

        # Check for onblur event
        if re.search(r'onblur\s*=', cookie_value, re.IGNORECASE):
            return True

        # Check for onchange event
        if re.search(r'onchange\s*=', cookie_value, re.IGNORECASE):
            return True

        # Check for onfocus event
        if re.search(r'onfocus\s*=', cookie_value, re.IGNORECASE):
            return True

        # Check for style attribute
        if re.search(r'style\s*=', cookie_value, re.IGNORECASE):
            return True

        # Check for expression function
        if re.search(r'expression\s*\(', cookie_value, re.IGNORECASE):
            return True

        # Check for url attribute
        if re.search(r'url\s*\(', cookie_value, re.IGNORECASE):
            return True

        # Check for onload attribute
        if re.search(r'onload\s*=', cookie_value, re.IGNORECASE):
            return True

        # Check for document.write function
        if re.search(r'document\.write\s*\(', cookie_value, re.IGNORECASE):
            return True

        # Check for eval function
        if re.search(r'eval\s*\(', cookie_value, re.IGNORECASE):
            return True

        # Check for alert function
        if re.search(r'alert\s*\(', cookie_value, re.IGNORECASE):
            return True

        # Check for prompt function
        if re.search(r'prompt\s*\(', cookie_value, re.IGNORECASE):
            return True

        # Check for confirm function
        if re.search(r'confirm\s*\(', cookie_value, re.IGNORECASE):
            return True

        # Check for window.location function
        if re.search(r'window\.location\s*\(', cookie_value, re.IGNORECASE):
            return True

        # Check for document.location function
        if re.search(r'document\.location\s*\(', cookie_value, re.IGNORECASE):
            return True

        # Check for document.cookie function
        if re.search(r'document\.cookie\s*\(', cookie_value, re.IGNORECASE):
            return True

        # No known XSS patterns found
        return False

            
        
    def cookie_sanitization_check(self,cookie):
            '''if cookie is having any sql injections '''
            if re.search(r';\s*(?:--|#)', cookie):
                return True
            
            
            if self.is_xss_in_cookie(cookie):
                return True
            
            
            '''if cookie is having any path tranversal commands'''
            if re.search(r'`|\$\(.*?\)', cookie):
                return True
            
            
            '''if cookie is having unicode encoding attacks'''
            if re.search(r'(%(?:c(?:0%|2%[abcefglnoprstuw])|3(?:2%[abcefhlnrtvy]|3[abd-fh-np-z])|4(?:1%[a-f]|2[abcefgilosty]|3[ace-gk-mq-suvwyz]|4[abd-hjkmnprstuwyz]|5[abcdefghijk-prstvwyz])|5(?:0%[a-fjqxz]|1[acefgkpruw]|2[adefghj-np-z]|3[cdfghkm-rtv-z]|4[abdeghijklmnoprt-vyz]|5[abdefghijklmnopqrstuvwxyz])|6(?:0%[a-dfgqxz]|1[abcdefghiklmnopqrstuvwxyz])))+', cookie):
                return True
        
            '''Check for base64 encoding attacks'''
            try:
                decoded_value = base64.b64decode(cookie)
                if re.search(r'<(script|iframe|object|embed|meta)', decoded_value, re.IGNORECASE):
                    return True
            except:
                pass
                
            
            return False