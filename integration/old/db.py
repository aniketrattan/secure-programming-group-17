

import tables

def get_name(local_user_id):
    return f"Bob+{local_user_id}"


def get_member_ids_of_group(group):
    return tables.local_users.keys()
