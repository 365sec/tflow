#ecoding :utf-8
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
def search_domain_classtype (domain):
    import domain_class
    import difflib
    for key, value in domain_class.domain_classtype.items():
        similar = float(difflib.SequenceMatcher(None, key, domain).quick_ratio())
        if similar - float(0.80) >= 0:
            return key, value
    return "", ""


print search_domain_classtype("www.sohu.com")