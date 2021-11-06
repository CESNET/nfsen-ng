<?php

namespace nfsen_ng\processor;

use nfsen_ng\common\{Debug, Config};

class FDSDump implements Processor {
    private $cfg = array(
        'env' => array(),
        'option' => array(),
        'format' => null,
        'output' => "csv",
        'filter' => array()
    );
    private $clean = array();
    private $d;
    private $fds2nfdfields = array("srcip" => "sa", "dstip" => "da", "srcport"
         => "sp", "dstport" => "dp", "proto" => "pr", "packets" => "opkt",
            "bytes" => "obyt", "flowStartMicroseconds:min" => "ts", "flowEndMicroseconds:max" => "te", "flows" => "fl",
            "biflowdir" => "dir");

    public static $_instance;

    function __construct() {
        $this->d = Debug::getInstance();
        $this->clean = $this->cfg;
        $this->reset();
    }

    public static function getInstance() {
        if (!(self::$_instance instanceof self)) {
            self::$_instance = new self();
        }
        return self::$_instance;
    }

    /**
     * Sets an option's value
     *
     * @param $option
     * @param $value
     */
    public function setOption($option, $value) {
        /*
          -h         Show this help
          -r path    FDS input file pattern (glob)
          -f expr    Input filter
          -F expr    Output filter
          -a keys    Aggregator keys (e.g. srcip,dstip,srcport,dstport)
          -s values  Aggregator values
          -O fields  Field to sort on
          -n num     Maximum number of records to write
          -t num     Number of threads
          -d         Translate IP addresses to domain names
          -o mode    Output mode (table, json, csv)
        */

        //$this->d->log('setOption(' . $option . ', ' . print_r($value) .')', LOG_DEBUG);

        switch ($option) {
            case '-M':
                $this->cfg['env']['sources'] = explode(':', $value);
                break;
            case '-R':
                $this->cfg['env']['flowdirs'] = $this->convert_date_to_path($value[0], $value[1]);
                break;
            case '-c':
                $this->cfg['option']["-n"] = $value;
                break;
            case '-a':
                if ($value[0] === "-") {
                    $this->cfg['option']["-a"] = substr($value, 2);
                } else {
                    $this->cfg['option']["-a"] = $value;
                }
                break;
            case '-r':
                $this->cfg['env']['flowdirs'] = $value;
                break;
            case '-O':
                $this->cfg['option']["-O"] = ($value == "tstart" ? "flowStartMicroseconds:min" : $value);
                break;
            case '-o':
                if (in_array($value, array("json", "table", "csv"))) {
                    $this->cfg['env']['output'] = $value;
                }
                break;
            default:
                $this->cfg['option'][$option] = $value;
                //$this->cfg['option']['-o'] = 'csv'; // always get parsable data todo user-selectable? calculations bps/bpp/pps not in csv
                break;
        }

        //$this->cfg['option']['-o'] = 'csv'; // always get parsable data todo user-selectable? calculations bps/bpp/pps not in csv
    }

    /**
     * Sets a filter's value
     *
     * @param $filter
     */
    public function setFilter($filter) {
        $this->cfg['filter'] = $filter;
    }

    /**
     * Executes the fdsdump command, tries to throw an exception based on the return code
     * @return array
     * @throws \Exception
     */
    public function execute() {
        $output = array();
        $processes = array();
        $return = "";
        $filter = (empty($this->cfg['filter'])) ? "" : " -f " . escapeshellarg($this->cfg['filter']);

        $flowfiles = "";
        foreach ($this->cfg['env']['sources'] as $source) {
            foreach ($this->cfg['env']['flowdirs'] as $fl) {
                $flowfiles .= " -r '" . $this->cfg['env']['profiles-data'] . $source . DIRECTORY_SEPARATOR . $fl ."'";
            }
        }

        if (!isset($this->cfg['option']['-s'])) {
            $aggr = " -s packets,bytes,flows,flowStartMicroseconds:min,flowEndMicroseconds:max";
        } else {
            $aggr = "";
        }

        if (!isset($this->cfg['option']['-a'])) {
            $aggrkey = " -a srcip,dstip,srcport,dstport,proto,biflowdir";
        } else {
            $aggrkey = "";
        }
        $output = " -o " . $this->cfg['env']['output'];
        $command = $this->cfg['env']['bin'] . $flowfiles . $output . " " . $this->flatten($this->cfg['option']) . $filter . $aggr . $aggrkey;
        $this->d->log('Trying to execute ' . $command, LOG_DEBUG);

        // check for already running fdsdump processes
        exec('ps -eo user,pid,args | grep -v grep | grep `whoami` | grep "' . $this->cfg['env']['bin'] . '"', $processes);
        if (count($processes) / 2 > intVal(Config::$cfg['fdsdump']['max-processes'])) throw new \Exception("There already are " . count($processes) / 2 . " processes of NfDump running!");

        // execute fdsdump
        exec($command, $output, $return);

        if ($this->cfg["env"]["output"] == "csv" and !isset($this->cfg["option"]["-I"])) {
            $lines = $output;
            array_unshift($lines, $command);

            $parsed_header = false;
            foreach ($lines as $i => &$line) {

                if ($i === 0) continue; // skip fdsdump command
                $line = str_getcsv($line, ',');
                if ($parsed_header === false) {
                    $new_header = array();
                    foreach ($line as $field_id => $field) {
                        $new_header[] = $this->fds2nfdfields[$field];
                    }
                    $line = $new_header;
                }

                $parsed_header = true;
                $line = array_values($line);
            }
        } else {
            return $output;
        }
        return $lines;


        // prevent logging the command usage description
        if (isset($output[0]) && preg_match('/^usage/i', $output[0])) $output = array();

        switch ($return) {
            case 127:
                throw new \Exception("NfDump: Failed to start process. Is fdsdump installed? " . implode(' ', $output));
                break;
            case 255:
                throw new \Exception("NfDump: Initialization failed. " . $command);
                break;
            case 254:
                throw new \Exception("NfDump: Error in filter syntax. " . implode(' ', $output));
                break;
            case 250:
                throw new \Exception("NfDump: Internal error. " . implode(' ', $output));
                break;
        }

        $output = array_slice($output, 0, -4);

        // slice csv (only return the fields actually wanted)
        $fields_active = array();
        $parsed_header = false;
        $format = false;
        if (isset($this->cfg['format']))
            $format = $this->get_output_format($this->cfg['format']);

        foreach ($output as $i => &$line) {

            if ($i === 0) continue; // skip fdsdump command
            $line = str_getcsv($line, ',');

            if (preg_match('/limit/', $line[0])) continue;
            if (preg_match('/error/', $line[0])) continue;
            if (!is_array($format)) $format = $line; // set first valid line as header if not already defined

            foreach ($line as $field_id => $field) {

                // heading has the field identifiers. fill $fields_active with all active fields
                if ($parsed_header === false) {
                    if (in_array($field, $format)) $fields_active[] = $field_id;
                }

                // remove field if not in $fields_active
                if (!in_array($field_id, $fields_active)) unset($line[$field_id]);
            }

            $parsed_header = true;
            $line = array_values($line);
        }
        return $output;
    }

    /**
     * Concatenates key and value of supplied array
     *
     * @param $array
     *
     * @return bool|string
     */
    private function flatten($array) {
        if (!is_array($array)) return false;
        $output = "";

        foreach ($array as $key => $value) {
            if (is_null($value)) {
                $output .= $key . ' ';
            } else {
                $output .= is_int($key) ?: $key . ' ' . escapeshellarg($value) . ' ';
            }
        }
        return $output;
    }

    /**
     * Reset config
     */
    public function reset() {
        $this->clean['env'] = array(
            'bin' => Config::$cfg['fdsdump']['binary'],
            'profiles-data' => Config::$cfg['fdsdump']['profiles-data'],
            'profile' => Config::$cfg['fdsdump']['profile'],
            'sources' => array(),
            'output' => "csv",
        );
        $this->cfg = $this->clean;
    }

    /**
     * Converts a time range to a nfcapd file range
     * Ensures that files actually exist
     *
     * @param int $datestart
     * @param int $dateend
     *
     * @return string
     * @throws \Exception
     */
    public function convert_date_to_path(int $datestart, int $dateend) {
        $start = new \DateTime();
        $end = new \DateTime();
        $start->setTimestamp((int)$datestart - ($datestart % 300));
        $end->setTimestamp((int)$dateend - ($dateend % 300));
        $filestart = $fileend = "";
        $filestartexists = false;
        $fileendexists = false;
        $sourcepath = $this->cfg['env']['profiles-data'] . DIRECTORY_SEPARATOR; //. $this->cfg['env']['profile'] . DIRECTORY_SEPARATOR;

        $this->d->log('start ' . $datestart .' end ' . $dateend, LOG_INFO);
        $timeslots = array();

        // if start file does not exist, increment by 5 minutes and try again
        while ($filestartexists === false) {
            if ($start >= $end) break;

            foreach ($this->cfg['env']['sources'] as $source) {
                $this->d->log('testfile ' . $sourcepath . $source . DIRECTORY_SEPARATOR . $filestart, LOG_INFO);
                if (file_exists($sourcepath . $source . DIRECTORY_SEPARATOR . $filestart)) {
                    //$fileendexists = true;
                    if ($filestart != "") {
                        $this->d->log('file ' . $filestart, LOG_INFO);
                        $timeslots[] = $filestart;
                    }
                }
            }

            $pathstart = $start->format('Y/m/d') . DIRECTORY_SEPARATOR;
            $filestart = $pathstart . 'flows.' . $start->format('YmdHi') . '00.fds';
            $start->add(new \DateInterval('PT5M'));
        }


        // if end file does not exist, subtract by 5 minutes and try again
        while ($fileendexists === false) {
            if ($end == $start) break; // strict comparison won't work

            foreach ($this->cfg['env']['sources'] as $source) {
                if (file_exists($sourcepath . $source . DIRECTORY_SEPARATOR . $fileend)) $fileendexists = true;
            }

            $pathend = $end->format('Y/m/d') . DIRECTORY_SEPARATOR;
            $fileend = $pathend . 'flows.' . $end->format('YmdHi') . '00.fds';
            $end->sub(new \DateInterval('PT5M'));
        }

        if ($fileend !== "") $timeslots[] = $fileend;

        return $timeslots;
    }

    /**
     * @param $format
     *
     * @return array|string
     */
    public function get_output_format($format) {
        // TODO - adapt to fdsdump!
        // todo calculations like bps/pps? flows? concatenate sa/sp to sap?
        switch ($format) {
            // fdsdump format: %ts %td %pr %sap %dap %pkt %byt %fl
            // csv output: ts,te,td,sa,da,sp,dp,pr,flg,fwd,stos,ipkt,ibyt,opkt,obyt,in,out,sas,das,smk,dmk,dtos,dir,nh,nhb,svln,dvln,ismc,odmc,idmc,osmc,mpls1,mpls2,mpls3,mpls4,mpls5,mpls6,mpls7,mpls8,mpls9,mpls10,cl,sl,al,ra,eng,exid,tr
            case 'line':
                return array('ts', 'td', 'pr', 'sa', 'sp', 'da', 'dp', 'ipkt', 'ibyt', 'fl');
                // fdsdump format: %ts %td %pr %sap %dap %flg %tos %pkt %byt %fl
            case 'long':
                return array('ts', 'td', 'pr', 'sa', 'sp', 'da', 'dp', 'flg', 'stos', 'dtos', 'ipkt', 'ibyt', 'fl');
                // fdsdump format: %ts %td %pr %sap %dap %pkt %byt %pps %bps %bpp %fl
            case 'extended':
                return array('ts', 'td', 'pr', 'sa', 'sp', 'da', 'dp', 'ipkt', 'ibyt', 'ibps', 'ipps', 'ibpp');

            default:
                return $format;
        }
    }
}

