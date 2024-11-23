import sys
import os

def get_vbs_path(filename):
    # The directory of the main file
    main_dir = os.path.dirname(os.path.abspath(sys.modules['__main__'].__file__))

    return os.path.join(main_dir, 'lib', 'vbscripts', filename)