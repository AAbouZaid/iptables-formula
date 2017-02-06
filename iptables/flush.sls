  {% from 'iptables/map.jinja' import firewall with context %}

  # If flush = true, set policy to ACCEPT and flush all.
  {% set flush = firewall.flush %}

  # If testing_mode.enabled = true, it will flush iptables after x minutes.
  {% set testing_mode_enabled = firewall.testing_mode.enabled %}
  {% set testing_mode_timer = firewall.testing_mode.flush_after|default(1)|int %}

  {%- if flush or testing_mode_enabled %}
    {% for chain in ['INPUT', 'OUTPUT', 'FORWARD'] %}
      {% for version in ['ipv4','ipv6'] %}
      iptables_{{ chain|lower }}_policy_accept_{{ version }}:
        iptables.set_policy:
          - table: filter
          - chain: {{ chain }}
          - family: {{ version }}
          - policy: ACCEPT
      {%- endfor %}
    {%- endfor %}

    {% for version in ['ipv4','ipv6'] %}
      iptables_flush_{{ version }}:
        iptables.flush:
          - table: filter
          - require:
            - iptables: iptables_input_policy_accept_{{ version }}
            - iptables: iptables_output_policy_accept_{{ version }}
            - iptables: iptables_forward_policy_accept_{{ version }}
    {%- endfor %}
  {%- endif %}

  {%- if testing_mode_enabled %}
      # Flush managed chains only.
      iptables_flush_testing_mode:
        module.run:
          - name: at.at
          - args:
            - "now +{{testing_mode_timer}} min"
            - |
              # IPv4
              iptables -P INPUT ACCEPT;
              iptables -P OUTPUT ACCEPT;
              iptables -P FORWARD ACCEPT;
              iptables -F INPUT;
              iptables -F OUTPUT;
              iptables -F FORWARD;
              # IPv6
              ip6tables -P INPUT ACCEPT;
              ip6tables -P OUTPUT ACCEPT;
              ip6tables -P FORWARD ACCEPT;
              ip6tables -F INPUT;
              ip6tables -F OUTPUT;
              ip6tables -F FORWARD;
  {%- endif %}
