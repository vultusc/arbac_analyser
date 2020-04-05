
import logging.config
import os
import time

from policy import Policy


def unpack_ua(ua_entries: []):
    """
    Create the first role assignments

    :param ua_entries: txt input from policy file
    :return: a dictionary
                - key -> user
                - values -> set of roles associated with the user
    """
    d_ua = {}

    for ua in ua_entries:
        ua_values = ua.split(",")
        key = ua_values[0][1:]
        value = ua_values[1][:-1]
        if (not key in d_ua.keys()):
            d_ua[key] = set()
        d_ua[key].add(value)

    return d_ua

def unpack_cr(cr_entries: []):
    """
    Create the list of can-revoke rules

    :param cr_entries: txt input from policy file
    :return: a list of tuple (ra, rt)
    """
    p_cr = []

    for ua in cr_entries:
        ua_values = ua.split(",")
        key = ua_values[0][1:]
        value = ua_values[1][:-1]
        p_cr.append((key, value))

    return p_cr

def unpack_ca(ca_entries: []):
    """
    Create the set of can-assign rules

    :param ca_entries: txt input from policy file
    :return: a list of dictionaries where:
                - ra: administrative role;
                - Rp: set of roles to be possessed;
                - Rn: set of roles that canno't be possessed;
                - rt: target role, role that can be assigned if all preconditions holds;
    """
    p_ca = []

    for ca in ca_entries:
        ca_values = ca.split(",")
        ra = ca_values[0][1:]
        rt = ca_values[-1][:-1]
        Rp = set()
        Rn = set()
        for roles in ca_values[1:-1]:
            if (roles != "true"):
                single_roles = roles.split("&")
                for r in single_roles:
                    if (r.startswith("-")):
                        Rn.add(r[1:])
                    else:
                        Rp.add(r)
        p_ca.append({
            "ra": ra,
            "Rp": Rp,
            "Rn": Rn,
            "rt": rt
        })

    return p_ca

def read_policy_file(policy_name: str, f_path_policy: str):
    """
    Create a policy object reading content from an external file

    :param policy_name: symbolic name for the policy
    :param f_path_policy: absolute path of policy file
    :return: a policy object
    """
    p = Policy()
    p.model.policy_name = policy_name

    if (os.path.exists(f_path_policy)):
        with (open(f_path_policy, "r")) as f_policy:
            lines = f_policy.readlines()
            if (len(lines) > 0):
                for l in lines:
                    l = l.lower()
                    values = l.split(" ")
                    key = values[0]              # First entry is the key
                    values = set(values[1:-1])   # Values (key and ';' are removed)
                    if (key == "roles"):
                        p.model.roles = values
                    elif (key == "users"):
                        p.model.users = values
                    elif (key == "ua"):
                        p.model.ua = unpack_ua(values)
                    elif (key == "cr"):
                        p.model.cr = unpack_cr(values)
                    elif (key == "ca"):
                        p.model.ca = unpack_ca(values)
                    elif (key == "goal"):
                        p.model.goal = values.pop()
    return p

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    t_exec = time.time()

    base_dir = "./policies"

    policies = os.listdir(base_dir)
    flag = [0 for i in range(8)]
    for f_name in policies:
        # Read a policy
        p = read_policy_file(f_name, "%s/%s" % (base_dir, f_name))

        # Simulate the policy
        target_reachable = p.simulate_policy()

        # Add the result to build the flag
        idx = int(f_name.split(".")[0][-1]) - 1
        flag[idx] = target_reachable

    logging.info("Flag=%s" % "".join(str(f) for f in flag))
    t_exec = time.time() - t_exec
    logging.debug("Total execution time: %0.3fs" % t_exec)

