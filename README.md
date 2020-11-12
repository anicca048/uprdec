# Uprdec
Uplink REDSHRT file decoder.

Useful tool for (de)obfuscating and rehashing Uplink REDSHRT files, to allow
inspection and modification of game saves / data files.

usage: uprdec.py \[-h\] \[-v\] \[-f\] mode input_file output_file

mode:   decode: removes obfuscation from input_file.
        encode: reobfuscates and rehashes data in input_file.
        strip:  removes REDSHRT header from input_file.

Note: input_file can not be modified in place.

Examples:   ./uprdec.py -v decode data.dat data.dat.dec
            ./uprdec.py -v strip data.dat.dec data.dat.zip
            
            cp <agent_name>.usr <agent_name>.usr.bak
            ./uprdec.py -v decode <agent_name>.usr <agent_name>.usr.dec
            <hex_editor> <agent_name>.usr.dec
            ./uprdec.py -v encode <agent_name>.usr.dec <agent_name>.usr

**This project is licensed under the terms of the MIT open source license.**
