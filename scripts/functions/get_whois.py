# Registrar
# Registrant
# CountryCode
# RegisteredCountry
# last update
# creation date

from datetime import datetime
import whois


def who_is(domain):
    """Function which uses the pyton_whois library to fetch whois data
    Arguments:
    domain - domain name, string

    Returns registrar data, update and creation value
    """
    
    try:
        res = whois.whois(domain)

        updated_date = res.updated_date
        if isinstance(updated_date, list):
            updated_date = str(updated_date[0]) 
        else:
            updated_date = str(updated_date)

        # Counting days between create/update and now, to calculate a value
        # Value 0 - no data
        # Value 1 - Domain is less than 30 days old / was updated less than 30 days ago
        # Value 2 - Domain is less than 90 days old (but older than 30 days) / less than 90 days ago
        # Value 3 - Domain is less than 365 days old (but older than 90 days) / less than 365 days ago
        # Value 4 - Domain is older than 365 days / more than 365 days ago

        striped_creation = datetime.strptime(str(res.creation_date), "%Y-%m-%d %H:%M:%S")
        days_since_creation = (datetime.now() - striped_creation).days

        striped_update = datetime.strptime(updated_date, "%Y-%m-%d %H:%M:%S")
        days_since_update = (datetime.now() - striped_update).days
        
        update_value = 0
        creation_value = 0

        if (days_since_creation < 30):
            creation_value = 1
        

        elif (days_since_creation >= 30 and days_since_creation < 91): 
            creation_value = 2
        

        elif (days_since_creation >= 91 and days_since_creation < 365):
            creation_value = 3

        elif (days_since_creation >= 365):
            creation_value = 4

        else:
            creation_value = 0


        if (days_since_update < 30):
            update_value = 1
        

        elif (days_since_update >= 30 and days_since_update < 91): 
            update_value = 2
        

        elif (days_since_update >= 91 and days_since_update < 365):
            update_value = 3

        elif (days_since_update >= 365):
            update_value = 4

        else:
            update_value = 0

 
        return res.registrar, res.registrant, creation_value, update_value, res.country
    
    # TODO: Error
    except Exception as e:
        print(f"Error fetching WHOIS data: {e}")
        return None


result = who_is("michaelkors.sk")
print(result)

# merrellvypredaj.sk
# meshkibratislava.sk
# mexxbratislava.sk
# michaelkors-kabelka.sk
# michaelkors-slovensko.sk
# michaelkors.sk
# michaelkorsbratislava.sk
# michaelkorskabelka.sk
# michaelkorssk.sk
# michaelkorsslovensko.sk
# microsoftonline.sk
# microsoftonlline.sk
# milujemeobuv.sk