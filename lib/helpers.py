import sys
import os

def get_vbs(filename):
    # The directory of the main file
    main_dir = os.path.dirname(os.path.abspath(sys.modules["__main__"].__file__))
    abs_path = os.path.join(main_dir, "lib", "vbscripts", filename)
    with open(abs_path) as f:
        vbs = f.read()
    return vbs