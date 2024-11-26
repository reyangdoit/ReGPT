import configparser, os


model = None
parsed_ini = None

def load_config():

    global model, parsed_ini
    parsed_ini = configparser.RawConfigParser()
    parsed_ini.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), "config.ini"))



def get_config(section, option):

    global parsed_ini

    if not parsed_ini:
        load_config()

    try:
        if parsed_ini and parsed_ini.get(section, option):
            return parsed_ini.get(section, option)
    except (configparser.NoSectionError, configparser.NoOptionError):
        print("config parse error. No correct section and option provide.")
        return ""
    
    raise ValueError("get_config error")


if __name__ == "__main__":

    # test
    load_config()
    print(get_config('RESE', "MODEL"))
    print(get_config("OPENAI", "x"))

