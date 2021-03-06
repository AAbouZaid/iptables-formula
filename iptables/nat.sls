# Generate rules for NAT
  {% set firewall = salt['pillar.get']('firewall', {}) %}
  {%- for service_name, service_details in firewall.get('nat', {}).items() %}  
    {%- for ip_s, ip_ds in service_details.get('rules', {}).items() %}
      {%- for ip_d in ip_ds %}
      iptables_in_{{service_name}}_allow_{{ip_s}}_{{ip_d}}:
        iptables.append:
          - table: nat 
          - chain: POSTROUTING 
          - jump: MASQUERADE
          - o: {{ service_name }} 
          - source: {{ ip_s }}
          - destination: {{ip_d}}
          - save: True
      {%- endfor %}
    {%- endfor %}
  {%- endfor %}