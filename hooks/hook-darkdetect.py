# PyInstaller hook for darkdetect (macOS theme detection)
#
# darkdetect/_mac_detect.py uses ctypes to load AppKit.framework, which is a
# system framework always present on macOS. PyInstaller's ctypes analysis
# only tracks basenames, so the full path 'AppKit.framework/AppKit' confuses
# it. We include the module but mark the framework as a system framework
# (excluded from bundling) since it's always available at runtime.
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['darkdetect._mac_detect']
