<?php

$list = $_SERVER['argv'];
$argv0 = array_shift($list);

//$list = glob('*.pck');
natsort($list);

// 
/*
Get HDRSIZE long
Get DUMMY long # version? (always =1)
Get GROUPS_HEADER_DATA_SIZE long
Get BKHD_HEADER_SIZE long
Get RIFF_HEADER_SIZE long
GoTo GROUPS_HEADER_DATA_SIZE 0 SEEK_CUR
Get GROUP_NAME string
Set EXT string "bnk"
CallFunction ExtractBlock
Set EXT string "xma"

idstring AKPK
get INFO_SIZE long
endian guess INFO_SIZE
get DUMMY long  # 1
get DUMMY long  # 24
get DUMMY long  # 154
get DUMMY long  # 41fbc
get DUMMY long  # 2
get DUMMY long  # 14
get DUMMY long  # 1
get DUMMY long  # 20
get DUMMY long  # 0
get NAME string
get FOLDER string

// each file record seems to be 24 bytes long

00000000  41 4b 50 4b ec 26 00 00  01 00 00 00 14 00 00 00  |AKPK.&..........| AKPK | header_len=9964 | version? | 20
00000010  04 00 00 00 04 00 00 00  bc 26 00 00 01 00 00 00  |.........&......| 4 | 4 | 9916(header_len-48) | 1
00000020  0c 00 00 00 00 00 00 00  73 00 66 00 78 00 00 00  |........s.f.x...| 12 | 0 | <- s f x (folder name in utf16?)
00000030  00 00 00 00 00 00 00 00**9d 01 00 00 fa de e4 48  |...............H| 413=filecount | 0x48e4defa
00000040  d7 0a 00 00 01 00 00 00  f0 89 02 00 f4 26 00 00  |.............&..| 2775 | 1 | 0x289f0=file_size | 00 00 26 f4 is offset of first file (header_len+8)
00000050  00 00 00 00 5a a9 f1 37  5a 14 0a 00 01 00 00 00  |....Z..7Z.......|
00000060  b0 d8 02 00 e4 b0 02 00  00 00 00 00 75 d6 d4 15  |............u...| <- 00 02 e4 b0 is offset of second? file
00000070  a6 30 0c 00 01 00 00 00  6c 73 00 00 94 89 05 00  |.0......ls......| <- 00 05 89 94 is offset of third? file
00000080  00 00 00 00 95 bb b6 63  e7 b4 11 00 01 00 00 00  |.......c........|
00000090  68 68 03 00 00 fd 05 00  00 00 00 00 66 74 93 60  |hh..........ft.`|
000000a0  4f 9b 14 00 01 00 00 00  d8 0d 03 00 68 65 09 00  |O...........he..|
000000b0  00 00 00 00 38 9a b9 5c  57 67 17 00 01 00 00 00  |....8..\Wg......|
000000c0  08 cb 00 00 40 73 0c 00  00 00 00 00 2c 02 eb 18  |....@s......,...|
000000d0  68 79 17 00 01 00 00 00  d0 8d 03 00 48 3e 0d 00  |hy..........H>..|
000000e0  00 00 00 00 50 b5 23 58  3c 72 18 00 01 00 00 00  |....P.#X<r......|
000000f0  44 8f 00 00 18 cc 10 00  00 00 00 00 07 c6 51 2e  |D.............Q.|
00000100  e2 4c 1c 00 01 00 00 00  8c f3 02 00 5c 5b 11 00  |.L..........\[..|


*/

class PckReader {
	private $fp;
	private $file;
	private $folder;
	private $header;
	private $files = [];

	public function __construct($file) {
		$this->file = $file;
		$this->fp = fopen($file, 'r');
		if (!$this->fp) throw new \Exception('failed to open file');
		$this->readHeader();
	}

	private function readHeader() {
		fseek($this->fp, 0);

		$head = fread($this->fp, 4);
		if ($head != 'AKPK') throw new \Exception('invalid header');

		list(,$headersize) = unpack('V', fread($this->fp, 4));
		$header = fread($this->fp, $headersize);

		// looks like genshin files are little endian
		$data = unpack('Vversion/Vghsize/Vsize1/Vsize2/Vsize3/Vvalue1/Vnamelen', $header);
		//var_dump($data);
		$header = substr($header, 4*7);
		$header = substr($header, $data['size1']); // skip bytes
		$this->header = $data;

		// read folder name?
		$fname = iconv('UTF-16LE', 'UTF-8', substr($header, 0, $data['namelen']));
		$pos = strpos($fname, "\0");
		if ($pos !== false) $fname = substr($fname, 0, $pos);

		$this->folder = $fname; // "sfx"
		//var_dump($fname);
		$header = substr($header, $data['namelen']); // +4; because why not
		//var_dump(strlen($header)); // == data_len

		$this->readFilelist(substr($header, 0, $data['size2']), 20);
		$this->readFilelist(substr($header, $data['size2'], $data['size3']), 24);
	}

	private function readFilelist($data, $reclen) {
		list(,$count_data) = unpack('V', $data);
		$data = substr($data, 4);
		echo 'Found '.$count_data.' files...'."\n";

		if (($count_data * $reclen) != strlen($data)) {
			var_dump($this->header);
			throw new \Exception("bad count $count_data vs ".(strlen($data)/24));
		}

		for($i = 0; $i < $count_data; $i++) {
			$info = substr($data, $reclen*$i, $reclen);
			// fadee448 d70a0000 01000000 f0890200 f4260000 00000000
			// crc?     key?     ??       len      offset   ??

			// 64a34123 01000000 968e4900 54010000 00000000
			// crc?     ??       len      offset   ??

			switch($reclen) {
				case 24:
					$info = unpack('Vcrc/Vkey/Vvalue1/Vlen/Voffset/Vvalue0', $info);
					break;
				case 20:
					$info = unpack('Vcrc/Vvalue1/Vlen/Voffset/Vvalue0', $info);
					break;
				default:
					throw new \Exception('unsupported reclen');
			}

			$this->files[] = $info;
		}
	}

	public function extract() {
		echo 'Extracting: '.$this->file." ...\n";

		foreach($this->files as $key => $info) {
			// extract file
			$fn = $this->file.'_'.$this->folder.'_'.$key;
			echo 'Extracting '.$fn." ...\n";
			$out = fopen($fn.'_raw.wav', 'w');
			stream_copy_to_stream($this->fp, $out, $info['len'], $info['offset']);
			fclose($out);

			system('/pkg/main/dev-games.vgmstream.core/bin/vgmstream-cli -o '.escapeshellarg($fn.'.wav').' '.escapeshellarg($fn.'_raw.wav'), $res);
			if ($res == 0)
				unlink($fn.'_raw.wav');

			//exit;
		}
	}
}

foreach($list as $file) {
	$pck = new PckReader($file);
	$pck->extract();
}
