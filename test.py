#!/usr/bin/python

from gad import make_tree_accessable

make_tree_accessable(tree_base,
        xgroups = [], wgroups = [], wxgroups = [], rgroups = [], rxgroups = [],
        rwgroups = [], rwxgroups = [],
        xusers = [], wusers = [], wxusers = [], rusers = [], rxusers = [],
        rwusers = [], rwxusers = [],
        safe_user = None, safe_group = None,
        ignore_paths = [], ignore_elements = [],
        ignore_links = True, ignore_base = False, recursive = True,
        group_sticky = True)

# vim:set tabstop=8 softtabstop=4 shiftwidth=4 et:
