import copy
import logging
import random
import time


class Policy(object):
    """
    Object that represent a policy
    """

    __MAX_PATIENCE_SLICING = 100
    __MAX_POLICY_ITERATIONS = 1000

    class PolicyModel(object):
        # A name for the policy
        policy_name = None

        # Set of all users
        users = None

        # Set of all roles
        roles = None

        # Set of initial user-role assignments
        ua = None

        # Lisy of can-revoke rules
        cr = None

        # List of can-assign rules
        ca = None

        # Target role
        goal = None

    __p = None

    def __init__(self):
        self.__p = Policy.PolicyModel()

    @property
    def model(self):
        return self.__p

    def __forward_slicing(self):
        """
        Apply the forward slicing algorithm

        :return: modify the internal policy
        """
        patience = self.__MAX_PATIENCE_SLICING

        # Create S0 with all assigned roles
        s_i = set()
        for user,roles in self.__p.ua.items():
            s_i.update(roles)

        rt_removals = set()
        while (patience > 0):
            # At every cycle s_ii is created empty
            s_ii = set()
            for idx,ca_rule in enumerate(self.__p.ca):
                # For all can-assign rules
                if (not idx in rt_removals):
                    # Skip already applied rules
                    ra = ca_rule["ra"]
                    rt = ca_rule["rt"]
                    Rp = ca_rule["Rp"].copy()
                    Rp.add(ra)
                    if (Rp.issubset(s_i)):
                        # Extends s_ii
                        s_ii.add(rt)
                        rt_removals.add(idx)
            s_ii.update(s_i)   # s_ii U s_i

            if (s_ii == self.__p.roles or s_i == s_ii):
                break  # No more extensions
            else:
                s_i = s_ii  # Try another extension
            patience -= 1

        if (patience >= 0):
            # Something can be reduced
            R_diff = self.__p.roles.difference(s_i)
            if (len(R_diff) > 0):
                # 1) Remove from CA all the rules that include any role in R_diff in the Rp or in rt
                # 3) Remove the roles R_diff from the negative preconditions of all rules
                tmp_ca = self.__p.ca.copy()
                self.__p.ca = []
                for ca in tmp_ca:
                    for role in R_diff:
                        if (role != ca["rt"] and not role in ca["Rp"]):
                            self.__p.ca.append(ca)
                            ca["Rn"].discard(role)

                # 2) Remove from CR all the rules that mention any role in R_diff
                tmp_cr = self.__p.cr.copy()
                self.__p.cr = []
                for cr in tmp_cr:
                    if (not (cr[0] in R_diff or cr[1] in R_diff)):
                        self.__p.cr.append(cr)

                # 3) Delete the roles R_diff
                self.__p.roles = self.__p.roles.difference(R_diff)

    def __backward_slicing(self):
        """
        Apply the backward slicing algorithm

        :return: modify the internal policy
        """
        patience = self.__MAX_PATIENCE_SLICING

        s_i = set()
        s_i.add(self.__p.goal)

        rt_removals = set()
        while (patience > 0):
            # At every cycle s_ii is created empty
            s_ii = set()
            for idx, ca_rule in enumerate(self.__p.ca):
                # For all can-assign rules
                if (not idx in rt_removals):
                    rt = ca_rule["rt"]
                    if ({rt}.issubset(s_i)):
                        s_ii.update(ca_rule["Rp"])
                        s_ii.update(ca_rule["Rn"])
                        s_ii.add(ca_rule["ra"])
                        rt_removals.add(idx)
            s_ii.update(s_i)

            if (s_ii == self.__p.roles or s_i == s_ii):
                break  # No more extensions
            else:
                s_i = s_ii  # Try another extension
            patience -= 1

        if (patience >= 0):
            # Something can be reduced
            R_diff = self.__p.roles.difference(s_i)
            if (len(R_diff) > 0):
                # 1) Remove from CA all the rules that assign a role in R_diff
                tmp_ca = self.__p.ca.copy()
                self.__p.ca = []
                for ca in tmp_ca:
                    if (not ca["rt"] in R_diff):
                        self.__p.ca.append(ca)

                # 2) Remove from CR all the rules that assign a role in R_diff
                tmp_cr = self.__p.cr.copy()
                self.__p.cr = []
                for cr in tmp_cr:
                    if (not cr[1] in R_diff):
                        self.__p.cr.append(cr)

                # 3) Delete the roles R_diff
                self.__p.roles = self.__p.roles.difference(R_diff)

    def __simulate_internal_policy(self):
        UR = self.__p.ua.copy()   # Starting assignment

        # Naive check, if verified we don't need to go further
        for u_check,R_check in UR.items():
            if (self.__p.goal in R_check):
                return 1

        q = []
        for u,R in UR.items():
            q.append((u, R))
        random.shuffle(q)

        patience = self.__MAX_POLICY_ITERATIONS

        while (patience >= 0):
            # For each user in the starting assignment...
            changed = False
            (u, R) = q.pop()

            for ca_rule in self.__p.ca:
                # Check can-assign rules where (r == ra)
                ra = ca_rule["ra"]
                if (ra in R):
                    # u has administrative rights...
                    rt = ca_rule["rt"]
                    Rp = ca_rule["Rp"]
                    Rn = ca_rule["Rn"]
                    for ut,Rt in UR.items():
                        if (not {rt}.issubset(Rt) and Rp.issubset(Rt) and len(Rn.intersection(Rt)) == 0):
                            # Extends u's assignments with the new role rt
                            if (not ut in UR.keys()):
                                UR[ut] = set()
                            UR[ut].add(rt)
                            if (rt == self.__p.goal):
                                return 1   # Found a valid assignment
                            changed = True

            if (not changed):
                for cr_rule in self.__p.cr:
                    # Check can-revoke rules where (r == ra)
                    ra = cr_rule[0]
                    if (ra in R):
                        rt = cr_rule[1]
                        for ut,Rt in UR.items():
                            if ({rt}.issubset(Rt)):
                                UR[ut].discard(rt)
                                changed = True

            patience -= 1
            q.insert(0, (u, R))

        return 0

    def simulate_policy(self, patience: int = 5000):
        """
        Simulate the execution of a policy to find a valid path to reach the target (goal) role

        :param patience: number oc iterations for convergence
        :return:
            - 1 - the target role is reachable
            - 0 - the target role is unreachable
        """
        t_exec = time.time()
        start_pol = copy.deepcopy(self.__p)

        for i in range(patience):
            self.__backward_slicing()
            self.__forward_slicing()

            target_reachable = self.__simulate_internal_policy()
            self.__p = start_pol
            if (target_reachable == 1):
                return target_reachable

        t_exec = time.time() - t_exec
        logging.debug("Policy %s checked in %0.3fs, target_reachable=%d" % (self.__p.policy_name, t_exec, target_reachable))

        return target_reachable
