"""
The simpleacl module is a wrapper layer around the posix1e module. It
attempts to simplify the handling of POSIX1e ACLs.

You will typically use the classes SimpleAcl, SimpleAccessAcl and
SimpleDefaultAcl to analyse and set ACLs.


Copyright (C) 2008 Fabian Knittel <fabian.knittel@avona.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA.
"""

import posix1e
from posix1e import ACL_READ, ACL_WRITE, ACL_EXECUTE


def permset_bits(permset):
    bits = 0
    for perm in [ACL_READ, ACL_WRITE, ACL_EXECUTE]:
        if permset.test(perm):
            bits |= perm
    return bits

def bits_as_permarray(bits):
    perms = []
    for perm in [ACL_READ, ACL_WRITE, ACL_EXECUTE]:
        if bits & perm:
            perms.append(perm)
    return perms

class SimpleAclEntry(object):
    """Wrapper around the posix1e Entry class to ease various operations, make
    the interface more pythonic, etc."""

    def __init__(self, acl, entry):
        self.acl = acl
        self.entry = entry

    def __str__(self):
        return "%s in %s" % (str(self.entry), str(self.acl))

    def get_permbits(self):
        return permset_bits(self.entry.permset)

    def set_permbits(self, bits):
        return self.set_perms(bits_as_permarray(bits))

    def fix_perms(self, required_perms = [], forbidden_perms = []):
        for perm in required_perms:
            if not self.entry.permset.test(perm):
                self.entry.permset.add(perm)
                self.acl.modified = True
        for perm in forbidden_perms:
            if self.entry.permset.test(perm):
                self.entry.permset.delete(perm)
                self.acl.modified = True

    def set_perms(self, perms = []):
        for perm in [ACL_READ, ACL_WRITE, ACL_EXECUTE]:
            if perm in perms:
                if not self.entry.permset.test(perm):
                    self.entry.permset.add(perm)
                    self.acl.modified = True
            else:
                if self.entry.permset.test(perm):
                    self.entry.permset.delete(perm)
                    self.acl.modified = True

    def delete(self):
        self.acl.acl.delete_entry(self.entry)
        self.acl.modified = True

    def get_tag_type(self):
        return self.entry.tag_type
    def set_tag_type(self, tag_type):
        self.entry.tag_type = tag_type
    tag_type = property(get_tag_type, set_tag_type)

    def get_qualifier(self):
        return self.entry.qualifier
    def set_qualifier(self, qualifier):
        self.entry.qualifier = qualifier
    qualifier = property(get_qualifier, set_qualifier)

    def get_permset(self):
        return self.entry.permset
    def set_permset(self, permset):
        self.entry.permset = permset
    permset = property(get_permset, set_permset)

class SimpleAcl(object):
    """Wrapper around the posix1e.ACL class to ease various operations, make
    the interface more pythonic, etc. Also introduces a flag whether the
    current state of the ACL is different from the one on disk."""

    def __init__(self, acl):
        self.acl = acl
        self.modified = False

    def __str__(self):
        return self.acl.__str__()

    def entries(self):
        for entry in self.acl:
            yield SimpleAclEntry(self, entry)

    def is_modified(self):
        return self.modified

    def _create_entry(self, type):
        entry = posix1e.Entry(self.acl)
        entry.tag_type = type
        self.modified = True
        return SimpleAclEntry(self, entry)

    def _get_entry(self, type, qual):
        for entry in self.acl:
            if entry.tag_type == type \
                    and entry.qualifier == qual:
                return SimpleAclEntry(self, entry)
        return None

    def has_group(self, gid):
        return self._get_entry(posix1e.ACL_GROUP, gid) is not None

    def get_group(self, gid):
        entry = self._get_entry(posix1e.ACL_GROUP, gid)
        if entry is None:
            entry = self._create_entry(posix1e.ACL_GROUP)
            entry.qualifier = gid
        return entry

    def get_user(self, uid):
        entry = self._get_entry(posix1e.ACL_USER, uid)
        if entry is None:
            entry = self._create_entry(posix1e.ACL_USER)
            entry.qualifier = uid
        return entry


    def _get_entry_obj(self, type):
        for entry in self.acl:
            if entry.tag_type == type:
                return SimpleAclEntry(self, entry)
        return None

    def get_user_obj(self):
        entry = self._get_entry_obj(posix1e.ACL_USER_OBJ)
        if entry is None:
            entry = self._create_entry(posix1e.ACL_USER_OBJ)
        return entry

    def get_group_obj(self):
        entry = self._get_entry_obj(posix1e.ACL_GROUP_OBJ)
        if entry is None:
            entry = self._create_entry(posix1e.ACL_GROUP_OBJ)
        return entry

    def get_other(self):
        entry = self._get_entry_obj(posix1e.ACL_OTHER)
        if entry is None:
            entry = self._create_entry(posix1e.ACL_OTHER)
        return entry

    def get_mask(self):
        entry = self._get_entry_obj(posix1e.ACL_MASK)
        if entry is None:
            entry = self._create_entry(posix1e.ACL_MASK)
        return entry


    def _filter_entries(self, type, quals):
        for entry in self.acl:
            if entry.tag_type == type:
                if entry.qualifier not in quals:
                    sentry = SimpleAclEntry(self, entry)
                    log_dbg("Deleting %s" % sentry)
                    sentry.delete()

    def filter_groups(self, gids = []):
        self._filter_entries(posix1e.ACL_GROUP, gids)

    def filter_users(self, uids = []):
        self._filter_entries(posix1e.ACL_USER, uids)

    def recalc_to_mask(self):
        """Adjust all permissions to the effective permissions as dictacted by
        the mask.

        On the one hand, this removes information. I.e. if the mask was only
        temporarily restricted, unrestricting the mask won't bring back the
        permissions.

        On the other hand, this greatly simplifies the code. If this turns
        out to be a problem in the future, we'll need to take the mask into
        account for every permission check during the code-run."""

        mask = self._get_entry_obj(posix1e.ACL_MASK)
        if mask is None:
            # There is no mask, so all perms are the effective perms.
            return

        # Calculate which perms are masked out by the ACL_MASK entry.
        forbidden_perms = bits_as_permarray(~mask.get_permbits())

        # Remove the masked-out permissions.
        for entry in self.entries():
            # Ignore the mask entry (obviously). Also ignore the user object
            # and other, as they aren't influenced by the mask.
            if entry.tag_type == posix1e.ACL_MASK or \
                    entry.tag_type == posix1e.ACL_USER_OBJ or \
                    entry.tag_type == posix1e.ACL_OTHER:
                continue
            entry.fix_perms(forbidden_perms = forbidden_perms)

    def calc_mask(self):
        """Recalculates the permission mask and returns whether the mask
        actually changed."""
        old_mask = self.get_mask().get_permbits()
        self.acl.calc_mask()
        if old_mask != self.get_mask().get_permbits():
            self.modified = True
            return True
        return False

    def valid(self):
        return self.acl.valid()

class InvalidAclError(Exception):
    pass

class SimpleAccessAcl(SimpleAcl):
    def __init__(self, file_path):
        self.path = file_path
        acl = posix1e.ACL(file = self.path)
        super(SimpleAccessAcl, self).__init__(acl)

    def __str__(self):
        return "access ACL for \"%s\"" % self.path
    def __repr__(self):
        return '<SimpleAccessAcl: %s, %s>' % (self.__str__(), self.acl)

    def apply(self, simulate = False):
        if not self.valid():
            raise InvalidAclError("attempt to apply invalid acl", self)
        if not simulate:
            self.acl.applyto(self.path, posix1e.ACL_TYPE_ACCESS)
        self.modified = False

class SimpleDefaultAcl(SimpleAcl):
    def __init__(self, file_path):
        self.path = file_path
        acl = posix1e.ACL(filedef = self.path)
        super(SimpleDefaultAcl, self).__init__(acl)

    def __str__(self):
        return "default ACL for \"%s\"" % self.path
    def __repr__(self):
        return '<SimpleDefaultAcl: %s, %s>' % (self.__str__(), self.acl)

    def apply(self, simulate = False):
        if not self.valid():
            raise InvalidAclError("attempt to apply invalid acl", self)
        if not simulate:
            self.acl.applyto(self.path, posix1e.ACL_TYPE_DEFAULT)
        self.modified = False
