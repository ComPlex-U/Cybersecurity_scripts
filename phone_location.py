import phonenumbers
from phonenumbers import geocoder, carrier, timezone

#number = "+351"
target = input('Enter the number to check: ')
phonne_number = phonenumbers.parse(target)

print(target)
print(timezone.time_zones_for_number(phonne_number))
print(carrier.name_for_number(phonne_number, 'en'))
print(geocoder.description_for_number(phonne_number, 'en'))
print("O numero é valido", phonenumbers.is_valid_number(phonne_number))
print("é possivel ligar", phonenumbers.is_possible_number(phonne_number))

