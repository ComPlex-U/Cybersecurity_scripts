import phonenumbers
from phonenumbers import geocoder
from phonenumbers import carrier
#number = "+351"
target = input('Enter the number to check: ')
phonne_number = phonenumbers.parse(target)

print(target)
print(geocoder.description_for_number(phonne_number,'en'))
print(carrier.name_for_number(phonne_number,'en'))