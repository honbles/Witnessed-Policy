# E4 codebook (every record is one vulnerability disclosure or incident in an SD-WAN / network management plane)
capability: C1 = code or command execution on the controller/manager host; C2 = configuration or database write through the management API (even if limited);
            C3 = confidentiality only (information disclosure, credential or key extraction); C4 = authentication bypass to administrative control.
policy_write: Y if exploitation lets the attacker ORIGINATE policy or configuration that edges accept today (C1, C2, C4); N for C3.
layer1: BLOCKS if policy_write = Y and the administrators' approval keys are NOT stored on the controller (edges reject entries without m-of-n approvals);
        NOT-ADDRESSED otherwise (confidentiality, controller availability and edge-device compromise are outside the design).
exploited: ITW = exploitation in the wild is stated in the cited source; NONE-AT-DISCLOSURE = vendor reported none; NS = not stated in the retrieved sources.
Second coding: capability_B, policy_write_B and layer1_B are filled independently of the A columns; `python3 kappa.py` reports Cohen's kappa per field.
