import "pe"
import "time"

private rule ft_strict_pe
{
  condition:
     // MZ signature at offset 0 and ...
     uint16(0) == 0x5A4D and
     // ... PE signature at offset stored in MZ header at 0x3C
     uint32(uint32(0x3C)) == 0x00004550
}

rule pyc_file_magic_v1
{
    strings:
        // 1.5
        $pyver_1_5_1 = { 99 4e 0d 0a }
        // 1.6
        $pyver_1_6_1 = { fc c4 0d 0a }

    condition:
        for any of ($pyver*) : ($ at 0)
}

rule pyc_file_magic_v2
{
    strings:
        // 2.0
        $pyver_2_0_1 = { 87 c6 0d 0a }
        // 2.1
        $pyver_2_1_1 = { 2a eb 0d 0a }
        // 2.2
        $pyver_2_2_1 = { 2d ed 0d 0a }
        // 2.3
        $pyver_2_3_1 = { 3b f2 0d 0a }
        $pyver_2_3_2 = { 45 f2 0d 0a }
        // 2.4
        $pyver_2_4_1 = { 59 f2 0d 0a }
        $pyver_2_4_2 = { 63 f2 0d 0a }
        $pyver_2_4_3 = { 6d f2 0d 0a }
        // 2.5
        $pyver_2_5_1 = { 77 f2 0d 0a }
        $pyver_2_5_2 = { 81 f2 0d 0a }
        $pyver_2_5_3 = { 8b f2 0d 0a }
        $pyver_2_5_4 = { 8c f2 0d 0a }
        $pyver_2_5_5 = { 95 f2 0d 0a }
        $pyver_2_5_6 = { 9f f2 0d 0a }
        $pyver_2_5_7 = { a9 f2 0d 0a }
        $pyver_2_5_8 = { b3 f2 0d 0a }
        // 2.6
        $pyver_2_6_1 = { c7 f2 0d 0a }
        $pyver_2_6_2 = { d1 f2 0d 0a }
        // 2.7
        $pyver_2_7_1 = { db f2 0d 0a }
        $pyver_2_7_2 = { e5 f2 0d 0a }
        $pyver_2_7_3 = { ef f2 0d 0a }
        $pyver_2_7_4 = { f9 f2 0d 0a }
        $pyver_2_7_5 = { 03 f3 0d 0a }

    condition:
        for any of ($pyver*) : ($ at 0)
}

rule pyc_file_magic_v3
{
    strings:
        // 3.0
        $pyver_3_0_1 = { b8 0b 0d 0a }
        $pyver_3_0_2 = { c2 0b 0d 0a }
        $pyver_3_0_3 = { cc 0b 0d 0a }
        $pyver_3_0_4 = { d6 0b 0d 0a }
        $pyver_3_0_5 = { e0 0b 0d 0a }
        $pyver_3_0_6 = { ea 0b 0d 0a }
        $pyver_3_0_7 = { f4 0b 0d 0a }
        $pyver_3_0_8 = { f5 0b 0d 0a }
        $pyver_3_0_9 = { ff 0b 0d 0a }
        $pyver_3_0_10 = { 09 0c 0d 0a }
        $pyver_3_0_11 = { 13 0c 0d 0a }
        $pyver_3_0_12 = { 1d 0c 0d 0a }
        $pyver_3_0_13 = { 1f 0c 0d 0a }
        $pyver_3_0_14 = { 27 0c 0d 0a }
        $pyver_3_0_15 = { 3b 0c 0d 0a }
        // 3.1
        $pyver_3_1_1 = { 45 0c 0d 0a }
        $pyver_3_1_2 = { 4f 0c 0d 0a }
        // 3.2
        $pyver_3_2_1 = { 58 0c 0d 0a }
        $pyver_3_2_2 = { 62 0c 0d 0a }
        $pyver_3_2_3 = { 6c 0c 0d 0a }
        // 3.3
        $pyver_3_3_1 = { 76 0c 0d 0a }
        $pyver_3_3_2 = { 80 0c 0d 0a }
        $pyver_3_3_3 = { 94 0c 0d 0a }
        $pyver_3_3_4 = { 9e 0c 0d 0a }
        // 3.4
        $pyver_3_4_1 = { b2 0c 0d 0a }
        $pyver_3_4_2 = { bc 0c 0d 0a }
        $pyver_3_4_3 = { c6 0c 0d 0a }
        $pyver_3_4_4 = { d0 0c 0d 0a }
        $pyver_3_4_5 = { da 0c 0d 0a }
        $pyver_3_4_6 = { e4 0c 0d 0a }
        $pyver_3_4_7 = { ee 0c 0d 0a }
        // 3.5
        $pyver_3_5_1 = { f8 0c 0d 0a }
        $pyver_3_5_2 = { 02 0d 0d 0a }
        $pyver_3_5_3 = { 0c 0d 0d 0a }
        $pyver_3_5_4 = { 16 0d 0d 0a }
        $pyver_3_5_5 = { 17 0d 0d 0a }
        // 3.6
        $pyver_3_6_1 = { 20 0d 0d 0a }
        $pyver_3_6_2 = { 21 0d 0d 0a }
        $pyver_3_6_3 = { 2a 0d 0d 0a }
        $pyver_3_6_4 = { 2b 0d 0d 0a }
        $pyver_3_6_5 = { 2c 0d 0d 0a }
        $pyver_3_6_6 = { 2d 0d 0d 0a }
        $pyver_3_6_7 = { 2f 0d 0d 0a }
        $pyver_3_6_8 = { 30 0d 0d 0a }
        $pyver_3_6_9 = { 31 0d 0d 0a }
        $pyver_3_6_10 = { 32 0d 0d 0a }
        $pyver_3_6_11 = { 33 0d 0d 0a }
        // 3.7
        $pyver_3_7_1 = { 3e 0d 0d 0a }
        $pyver_3_7_2 = { 3f 0d 0d 0a }
        $pyver_3_7_3 = { 40 0d 0d 0a }
        $pyver_3_7_4 = { 41 0d 0d 0a }
        $pyver_3_7_5 = { 42 0d 0d 0a }
        // 3.8
        $pyver_3_8_1 = { 48 0d 0d 0a }
        $pyver_3_8_2 = { 49 0d 0d 0a }
        $pyver_3_8_3 = { 52 0d 0d 0a }

    condition:
        for any of ($pyver*) : ($ at 0)
}

rule pyc_file_magic_bad_mod_timestamp
{
    condition:
        (pyc_file_magic_v2 or pyc_file_magic_v3) and
        // is the current time within the bounds of v1.5 release and now
        // https://en.wikibooks.org/wiki/Python_Programming/Version_history
        (uint32(4) < 883486799 or
        uint32(4) > time.now())
}

rule pyinstaller
{
    strings:
        $a = "python"
        $b = "Python"
        $c = "Py_SetPythonHome"
        $d = "uncompyle6"
    condition:
        $a and $b and $c and not $d
}

rule lazy_zip_append
{
	strings:
		$eocd_sig = { 50 4B 05 06 }

	condition:
		uint32(0) == 0x04034b50 and uint32(4) != 0x00060014 and $eocd_sig and uint16(@eocd_sig[#eocd_sig] + 20) != filesize - (@eocd_sig[#eocd_sig] + 22)
}

rule nibble_shifted_ole
{
    strings:
        $shiftole = { 0d 0c f1 1e 0a 1b 11 ae 1? }

    condition:
        $shiftole
}

rule sfx_rar_pdb
{
    strings:
        $32bitpdb = "d:\\Projects\\WinRAR\\SFX\\build\\sfxrar32\\Release\\sfxrar.pdb"
    condition:
        ft_strict_pe and $32bitpdb
}

rule misc_upx_packed_binary
{
   condition:
      (pe.sections[0].name == "UPX0" and pe.sections[1].name == "UPX1")
}

rule object_linking_embedding_compound_file
{
    strings:
        $olecf = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $olecf at 0
}