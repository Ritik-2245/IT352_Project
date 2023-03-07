from http import cookies
import re


class CAE:
    mal=["javascript:","base64","eval","<script","<iframe","advertising","onload=","expression(","onload","onerror","onclick"]
    advertising_cookie_names = [
        "ad_",
    "affiliate_","promo_", "advertising_","banner_","campaign_","click_","offer_","partner_","referral_","sponsor_","tracking_", "adserver_","adtech_","advertising_","adwords_","analytics_","banner_","click_","conversion_","counter_","display_","doubleclick_","flash_","google_","hit_","impression_","media_","offer_","partner_","pixel_","promo_","referral_","remarketing_","retargeting_","server_","sponsor_","stats_","tracking_","traffic_","visitor_","webtrends_","yahoo_","yandex_","ad_","adbloc","adblock","adclick","adclient","adcookie","adexchange","adform","adframe","adimage","adimg","adip","adkey","adlink","adlog","adman","admax","admedia","admeta","adnet","adnetwork","adpage","adparam","adplace","adplay","adplus","adpost","adproxy","adrotate","adserver","adserv","adsframe","adsite","adspace","adspot","adstat","adtech","adtext","adunit","adview","adwords","adzone","affiliat","analytics","banner","banners","bid","bidder","bidrequest","bidresponse","bids","bidswitch","bidtracker","bidwin","bim","blitz","click","clicks","clicktag","clicktracker","clicktracking","clickx","client","clients","cm","cmclick","cmtracker","cmtracking","cmx","conversion","counter","counters","cpm","cpmclick","cpmtracker","cpmtracking","cpmx","creative","creatives","criteo","ctr","ctracker","ctracking","ctrclick","ctrtracker","ctrtracking","ctrx","cx","data","dcm","dcmclick","dcmtracker","dcmtracking","dcmx","display","doubleclick","doubleclickclick","doubleclicktracker","doubleclicktracking","doubleclickx","dsp","dtp","dtpclick","dtptracker","dtptracking","dtpx","flash","flashclick","flashtracker","flashtracking","flashx","google","googleclick","googletracker","googletracking","googlex","hit","hits","impression","impressions","impressiontracker","impressiontracking","impressionx","instream","instreamclick","instreamtracker","instreamtracking","instreamx","interstitial","interstitialclick","interstitialtracker","interstitialtracking","interstitialx","js","jsclick","jstracker","jstracking","jsx","media","mediaclick","mediatracker","mediatracking","mediax","offer","offers","offertracker","offertracking","offerx","partner","partners","pixel","pixels","pixeltracker","pixeltracking","pixelx","pop","popclick","poptracker","poptracking","popx","promo","promoclick","promotracker","promotracking","promox","referral"]
    
    def check_char(self,cookie):
        if re.search(r"[;=\n]", cookie):
            return True
        try:
            cookie = cookies.SimpleCookie(cookie)
        except:
            return True
        
        return False
    
    def key_value(self,cookie):
        for key in cookie:
            value = cookie[key].value
        
        for m in CAE.mal:
            if m in value.lower():
                return True
        return False
    
    def validate_cookie(self,cookie):
        forbidden_chars = [';', '=']
        for char in forbidden_chars:
            if char in cookie:
                return False
            
    # Check that the cookie only contains valid characters
        if not all(c.isalnum() or c.isspace() for c in cookie):
            return False
    
        return True
    
    def is_advertising_cookie(self,cookie):
    # Check the cookie name for advertising keywords
        for keyword in CAE.advertising_cookie_names:
            if keyword in cookie:
                return True
    
        return False
    
    def sanitize_cookie(cookie):
        pattern = re.compile("^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")
        if pattern.match(cookie):
            return cookie
        else:
            return None
