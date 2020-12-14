import phonenumbers
from phonenumbers import geocoder
from phonenumbers import carrier
number = "+351"

phonne_number = phonenumbers.parse(number)

print(number)
print(geocoder.description_for_number(phonne_number,'en'))
print(carrier.name_for_number(phonne_number,'en'))