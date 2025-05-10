from datetime import datetime
import whois

def age_to_bucket(days):
    """Categorizing results into numbers/buckets of 1-4 or if error or missing returns -1"""
    if days < 0:
        return -1
    elif days < 30:
        return 1
    elif days < 91:
        return 2
    elif days < 365:
        return 3
    else:
        return 4
    

def who_is(domain):
    try:
        res = whois.whois(domain)

        registrar = res.registrar if res.registrar else "Unknown"

        # Creation
        try:
            creation_date = res.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            creation_days = (datetime.now() - creation_date).days
            creation_bucket = age_to_bucket(creation_days)
        except Exception:
            creation_bucket = -1
            creation_date = None

        # Update
        try:
            updated_date = res.updated_date
            if isinstance(updated_date, list):
                updated_date = updated_date[0]
            update_days = (datetime.now() - updated_date).days
            update_bucket = age_to_bucket(update_days)
        except Exception:
            update_bucket = -1


        return registrar, creation_bucket, update_bucket
    
    except Exception:
        return "Unknown", -1, -1


