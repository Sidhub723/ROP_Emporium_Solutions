from pwn import *

#uncomment the print statements to see the masking in action
def maskfinder():
    hardcoded_ebx = 0xb0bababa
    final_string = 'flag.txt'
    finalMask = []

    for c in final_string:
        # print("key: "+ str(hex(hardcoded_ebx) + " (" + ''.join(num for num in bits_str(hardcoded_ebx)) + ")" ))

        mask = ''
        index = 0
        char_count = 0
        hardcoded_ebx_reversed = bits(hardcoded_ebx, endian='little')
        character_reversed = bits(u8(c), endian='little')

        while char_count < len(character_reversed) - 1:
            if(hardcoded_ebx_reversed[index] == character_reversed[char_count]):
                mask += "1"
                char_count += 1
            else:
                mask += "0"
            index += 1

        mask += "0" * (16 - len(mask))
        mask = ''.join(reversed(mask))
        finalMask.append(mask)

        ##### print("mask: " + str(hex(u16(unbits(mask))) + (35 - len(mask) * " ") + "(" mask + ")"))
        # print("mask: " + str(hex(u16(unbits((mask))))) + ((35 - len(mask)) * " ") + " (" + mask + ")")
        # print("char (" + c + ")" + ": "+ str(hex(u8(c))) + (25 * " ") + " (" + ''.join(num for num in bits_str(u8(c))) + ")\n" )

    hex_mask = [hex(u16(unbits((i)), endian='big')) for i in finalMask]
    return hex_mask
