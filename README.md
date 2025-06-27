# Inxpect

## Readme work in progress

Read the [installation](/inxpect/INSTALL.md) file to know how to install the `Inxpect` tool.

Read the [setting](/inxpect/SETTING.md) file to know how to set the right PMC register and the right event to monitor.

See [examples](/inxpect/examples) folder to see some examples of how to add sections to your XDP program.

## Other advices

Inxpect not disable the event counter in the end of the program sometimes. Specially when more than 1 section is used. In order to reset the event counter, you need to edit the `clean_reg.sh` file setting your register and run it:

> [!CAUTION]
> This command will reset the event counter and the PMC registers. This will disable the monitoring of the events. Be sure to set the right PMC register in the file
```bash
sudo ./clean_reg.sh -1
```
