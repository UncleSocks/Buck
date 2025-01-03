import os


def file_path_parser(file_path="backdoordiplomacy_filepath_iocs.txt"):

    with open(file_path, "r") as file:

        file_path_iocs = {}
        for line in file:
            ioc = line.strip()

            if not ioc:
                continue

            directory, filename = os.path.split(ioc)
            
            if directory not in file_path_iocs:
                file_path_iocs[directory] = []

            file_path_iocs[directory].append(filename)

    return file_path_iocs


def python_to_powershell(file_path_iocs):

    ps_hashtable = []

    for file_path in file_path_iocs:
        ps_hashtable_entry = f'\n@{{ Path = "{file_path}\\" \n   Files = @(\n'        
        files = ',\n'.join(f'   "{file}"' for file in file_path_iocs[file_path])
        ps_hashtable_entry += f'{files}\n   )'
        ps_hashtable_entry += f'\n}}'

        ps_hashtable.append(ps_hashtable_entry)
        
    ps_hashtable_output = ','.join(ps_hashtable)
    
    return ps_hashtable_output


print(python_to_powershell(file_path_parser()))