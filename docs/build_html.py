#!/usr/bin/env python3

import os
import sys
import sphinx.cmd.build

make_mode = 'html'
base_dir = sys.path[0]
rst_dir =  os.path.join(base_dir, 'rst')
sphinx.cmd.build.main(['-M', make_mode, rst_dir, base_dir])
