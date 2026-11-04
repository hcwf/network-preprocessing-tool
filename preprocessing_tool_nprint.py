
from abc import ABC, abstractmethod
from typing import Any
from enum import Enum
import pandas as pd
import dataclasses
import subprocess
import argparse
import tempfile
import signal
import sys
import os

# Rows of nPrint output processed at a time. nPrint rows are very wide (well over a thousand columns),
# so this keeps memory use to a few GB however large the capture is.
NPRINT_CHUNK_ROWS = 50_000

# used for input 

@dataclasses.dataclass
class SinglePcapConfigTemplate():
    '''
    SinglePcapConfigTemplate defines a pipeline for only one directory to process pcaps
    '''

    headers: list[str]
    masks_type: str
    masks: list[str]
    input_file: str
    output_file: str
    packets_to_read: int | str = 'max'   # 'max' = every packet (no -c given to nPrint); 0 = do nothing


class Mask(ABC):
    '''
    Mask defines the interface that any masker object must implement. Mask objects delete information
    from dataframes.
    '''    
    
    def __init__(self, strings: list[str]) -> None:
        '''
        __init__ initalizes the object

        @param strings: columns of the dataframe to delete information from. Might not be directly
        the columns.
        '''
        
        self._strings = strings

    @abstractmethod
    def mask(self, dataframe: pd.DataFrame) -> None:
        '''
        mask deletes information from a dataframe, specifically it's columns 

        @param dataframe: dataframe from which to delete information. Modifications are done in inplace
        '''
        
        pass    

class PrefixDeletionMask(Mask):
    '''
    PrefixDeletionMask will work by eliminating the columns that match the prefixes it is given.
    Non existent columns will be simply ignored.
    '''

    def __init__(self, strings: list[str]) -> None:
        super().__init__(strings)

    def mask(self, dataframe: pd.DataFrame) -> None:
        prior_columns = list(dataframe.columns)
        already_deleted = set()

        for prefix in self._strings:
            for candidate_column in prior_columns:
                if candidate_column.startswith(prefix) and (candidate_column not in already_deleted):
                    dataframe.drop(candidate_column, axis = 1, inplace = True)
                    already_deleted.add(candidate_column)

class MaskType(Enum):
    '''
    MaskType are the types of mask you can ask for
    '''
    
    prefix_delete = "prefix_delete"

class MaskingCapabilities(Enum):
    '''
    MaskingCapabilities are the types of protocols you may attempt to mask
    '''
    
    ethernet = 'ethernet'
    arp = 'arp'
    ipv4 = 'ipv4'
    ipv6 = 'ipv6'
    tcp = 'tcp'
    udp = 'udp'
    ip = 'ip'
    icmp = 'icmp'

class IMaskFactory(ABC):
    '''
    IMaskFactory specifies the interface any mask factory must have
    '''
    
    @abstractmethod
    def generate_mask(self, mask_type: MaskType, to_mask: MaskingCapabilities) -> Mask:
        '''
        generate_mask is the function that takes care of creating mask objects given input

        @param mask_type: the type of mask you want
        @param to_mask: what you want to mask
        @returns: a mask that can do what you asked for 
        '''
        
        pass

class MaskFactory(IMaskFactory):
    '''
    MaskFactory is the default factory to generate masks
    '''

    def _mask_to_prefixes(self, to_mask: MaskingCapabilities) -> list[str]:
        '''
        _mask_to_prefixes generates prefixes that can be used with a prefix mask

        @param to_mask: what you want to mask
        @returns: a list of prefixes to erase from nPrint's output
        '''
        
        if to_mask == MaskingCapabilities.ethernet:
            return ['eth_dhost','eth_shost']
        elif to_mask == MaskingCapabilities.arp:
            return ['arp_sha' ,'arp_spa' ,'arp_tha', 'arp_tpa']
        elif to_mask == MaskingCapabilities.ipv4:
            return ['ipv4_src','ipv4_dst']
        elif to_mask == MaskingCapabilities.ipv6:
            return ['ipv6_src' ,'ipv6_dst']
        elif to_mask == MaskingCapabilities.tcp:
            return ['tcp_sprt','tcp_dprt']
        elif to_mask == MaskingCapabilities.udp:
            return ['udp_sport','udp_dport']
        elif to_mask == MaskingCapabilities.ip:
            return ['src_ip']
        elif to_mask == MaskingCapabilities.icmp:
            return []

        raise ValueError("Gave _mask_to_prefixes an incorrect to_mask")

    def generate_mask(self, mask_type: MaskType, to_mask: MaskingCapabilities) -> Mask:
        if mask_type == MaskType.prefix_delete:
            prefixes = self._mask_to_prefixes(to_mask)
            return PrefixDeletionMask(prefixes)

class INprinter(ABC):
    '''
    Nprinter represents a class that can convert a pcap file into the format of nprint. This superclass
    defines the common interface any concrete class should implement.
    '''
    
    def __init__(self) -> None:
        '''
        __init__ will initialize the class
        '''
        
        self._options = {}
        self._target_file = None
        # nPrint binary next to this script, so the tool works from any working directory
        self._executable = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'nprint', 'nprint')
        self._header_to_flag = {
            'ethernet':'-e',
            'ipv4':'-4',
            'ipv6':'-6',
            'absolute_time':'-A',
            'icmp':'-i',
            'tcp':'-t',
            'udp':'-u',
            'relative_time': '-R',
            'arp': '-a'
        }

    def set_flag(self, flag: str | tuple[str,str]) -> None:
        '''
        Set a flag to be used when executing nprint. Either use the "-flag" format or ("-flag","value") 
        format. All possible flags are the ones defined by nprint.

        @param flag: The flag to add when executing nprint
        '''
        
        if type(flag) is tuple:
            self._options[flag[0]] = flag[1]
        else:
            self._options[flag] = None

    def remove_flag(self, flag: str) -> None:
        '''
        remove_flag removes a flag of the form "-flag" from the arguments when executing nprint

        @param flag: the flag to remove when executing nprint
        '''
        
        if flag in self._options:
            self._options.pop(flag)
        
    def add_header(self, header: str) -> None:
        '''
        add_header allows to add the specified header to the output of nprint. Internally this
        is saved as a flag. 

        @param header: a string specifying the header to get from a packet to the output
        '''
        
        flag = self._header_to_flag[header]
        self.set_flag(flag)

    def remove_header(self, header: str) -> None:
        '''
        remove_header removes the specified header to the output of nprint.

        @param header: a string specifying the header to remove from a packet from the output
        '''
        
        flag = self._header_to_flag[header]
        self.remove_flag(flag)

    def set_pcap_file(self, path: str) -> None:
        '''
        set_pcap_file will set the file to extract packets from.

        @param path: the path to the pcap file.
        '''
        
        self.set_flag(('-P',path))

    def set_target_file(self, path: str) -> None:
        '''
        set_target_file sets the file data will be written to. Tstrhe format is csv.

        @param path: the path to the csv file.
        '''
        
        self.set_flag(('-W',path))
    
    def _create_args(self) -> list[str]:
        '''
        _create_args creates the arguments to execute as a subprocess, given the internal state of the object.

        @returns: list containing the arguments to be executed as a subprocess.
        '''
        
        args = [self._executable]
        for flag, value in self._options.items():
            args.append(flag)
            if value is not None:
                args.append(value)
        return args

    @abstractmethod
    def execute(self) -> None:
        '''
        execute executes nprint given with the configuration specified by the user.
        '''
        pass

class Nprinter(INprinter):
    '''
    StandardNprinter is the default to go class when executing nprint
    '''
    
    def execute(self) -> None:
        args = self._create_args()
        nprint_process = subprocess.Popen(args, stdout=subprocess.PIPE)
        try:
            nprint_process.wait()
        finally:
            if nprint_process.poll() is None:   # interrupted: do not leave nPrint running
                nprint_process.kill()
                nprint_process.wait()
        if nprint_process.returncode != 0:
            # Processing continues with what was written, as before, but the failure is not hidden.
            print(f"nPrint exited with code {nprint_process.returncode}; the output may be incomplete.", file=sys.stderr)

class IPcap2Series(ABC):
    '''
    IPcap2Series defines the interface all objects that translate a pcap to an object must implement
    '''
    
    def __init__(
        self,
        headers: list[str],
        masks_type: str,
        masks: list[str],
        flags: list[tuple[str,str]|str]
    ) -> None:
        '''
        __init__ initalizes the object

        @param headers: the headers from the pcap you want to include 
        @param masks_type: the type of mask you want. See i2rced.processing.masks_generators.MaskType for values
        @param masks: the masks you want to apply. See i2rced.processing.masks_generators.MaskingCapabilities for
        values
        @param flags: flags you want to pass to the underlying process
        '''
        
        self._headers = headers
        self._masks_type = masks_type
        self._masks = masks

        self._mask_factory = MaskFactory()
        self._maskers = [
            self._mask_factory.generate_mask(
                MaskType(masks_type),
                MaskingCapabilities(mask)
            ) for mask in masks
        ]

        self._temp_dir = None   # where nPrint's intermediate CSV goes (default: system temp dir)

        self._nprinter = Nprinter()
        for header in headers:
            self._nprinter.add_header(header)
        for flag in flags:
            self._nprinter.set_flag(flag)

    def set_temp_dir(self, path: str | None) -> None:
        '''
        set_temp_dir sets the folder for nPrint's intermediate CSV. It is as large as the final output, so it
        should be on a disk with room for it (the system temp dir is often small or in memory).

        @param path: an existing folder, or None for the system default
        '''

        self._temp_dir = path

    def set_read_packets(self, number: str | int) -> None:
        '''
        set_read_packets sets the number of packets you want to read from the file

        @param number: the number to read, either int, string, or "max".
        '''
        
        if number == 'max':
            self._nprinter.remove_flag('-c')
        else:
            self._nprinter.set_flag(('-c',str(number)))
        
    def _pcap_to_dataframe(self, printer: INprinter, pcap_file: str) -> pd.DataFrame:
        '''
        _pcap_to_dataframe transforms a pcap file to a dataframe using a printer

        @param printer: printer to use
        @param pcap_file: the path to the file you want
        @returns: the dataframe of the processed pcap
        '''
        
        # set the file
        printer.set_pcap_file(pcap_file)

        # get a temporary output file
        temporary_output = tempfile.NamedTemporaryFile(suffix='.csv')

        # set the target file
        printer.set_target_file(temporary_output.name)

        # execute, and read the dataframe. The temporary file will be destroyed
        printer.execute()
        dataframe = pd.read_csv(temporary_output.name)
        return dataframe

    def _pcap_to_dataframe_chunks(self, printer: INprinter, pcap_file: str, chunk_rows: int):
        '''
        _pcap_to_dataframe_chunks is _pcap_to_dataframe without holding the whole result in memory: it yields
        the dataframe of nPrint's output chunk_rows rows at a time.

        @param printer: printer to use
        @param pcap_file: the path to the file you want
        @param chunk_rows: rows per dataframe
        '''

        printer.set_pcap_file(pcap_file)

        with tempfile.NamedTemporaryFile(suffix='.csv', dir=self._temp_dir) as temporary_output:
            printer.set_target_file(temporary_output.name)
            printer.execute()
            try:
                yield from pd.read_csv(temporary_output.name, chunksize=chunk_rows)
            except pd.errors.EmptyDataError:
                return   # nPrint wrote nothing: no packets

    @abstractmethod
    def pcap_to_object(self, pcap_path: str) -> Any:
        '''
        pcap_to_object is the function to convert a pcap into any type of object. 

        @param pcap_path: the path to the pcap file
        @returns: an object representing that file
        '''
        
        pass

class Pcap2PandasSeries(IPcap2Series):
    '''
    Pcap2PandasSeries converts a file into a pandas dataframe
    '''
    
    def pcap_to_object(self, pcap_path: str) -> pd.DataFrame:
        
        dataframe = self._pcap_to_dataframe(self._nprinter, pcap_path)

        for masker in self._maskers:
            masker.mask(dataframe)

        return dataframe

    def pcap_to_chunks(self, pcap_path: str, chunk_rows: int):
        '''
        pcap_to_chunks yields the masked dataframe of a file chunk_rows rows at a time
        '''

        for dataframe in self._pcap_to_dataframe_chunks(self._nprinter, pcap_path, chunk_rows):
            for masker in self._maskers:
                masker.mask(dataframe)
            yield dataframe
            

class IPipeline(ABC):
    '''
    IPipeline defines the interface all pipelines must implement
    '''
    
    @abstractmethod
    def run(self) -> None:
        '''
        run executes the pipeline, any configuration information must be given beforehand
        '''
        
        pass
    
class PcapPipeline(IPipeline):
    '''
    PcapPipeline is the class pipelines that treat with pcaps should inherit from
    '''
    
    def __init__(
        self, 
        configuration_template: Any
    ) -> None:
        '''
        __init__ defines how PcapPipelines should be initialized. Any class can change the specific type 
        of configuration template to use.
        '''

        pass

class SinglePcapPipeline(PcapPipeline):
    
    def __init__(self, configuration_template: SinglePcapConfigTemplate) -> None:

        self._configuration_template = configuration_template
        
        self._pcap2series_converter = Pcap2PandasSeries(
            configuration_template.headers, 
            configuration_template.masks_type, 
            configuration_template.masks,
            []
        )
        # the intermediate CSV is as large as the output: keep it on the output's disk
        self._pcap2series_converter.set_temp_dir(
            os.path.dirname(os.path.abspath(configuration_template.output_file))
        )
    
    def _add_series_identifier(
        self, 
        dataframe: pd.DataFrame, 
        instances_per_series: int, 
        starting_point: int
    ) -> int:
        '''
        _add_series_identifier will add to a dataset inplace an identifier for series. The identifiers will 
        be incremental and will start at starting_point. The function returns the maximum idetifier reached

        @param dataframe: dataframe to add a series identifier to
        @param instances_per_series: number of packets per series
        @param starting_point: number to start when giving identifiers.
        @returns: the maximum identifier reached
        '''
        
        num_rows = dataframe.shape[0]

        dataframe['series_id'] = range(num_rows)
        dataframe['series_id'] //= instances_per_series
        dataframe['series_id'] += starting_point

        return dataframe['series_id'].max()

    def _drop_extra_packets(
        self,
        dataframe: pd.DataFrame,
        instances_per_series: int
    ) -> pd.DataFrame:
        '''
        _drop_extra_packets will drop extra rows from a dataframe and return the modified one. The new dataframe
        will have a number of rows multiple of instances_per_series

        @param dataframe: the original dataframe
        @param instances_per_series: the number you want the size of the dataframe to be a multiple of
        @return: the modified dataframe
        '''
        
        # tried to find an inplace operation for this but did not find it
        to_delete = (dataframe.shape[0] % instances_per_series)
        if to_delete > 0:
            dataframe = dataframe[:-to_delete]
        return dataframe

    def _read_n_packets(
        self,
        pcap2series: Pcap2PandasSeries,
        number_of_packets: int,
        filepath: str
    ) -> pd.DataFrame:
        '''
        _read_n_packets will read number_of_packets from a file in filpath and covert it to a pandas
        dataframe using pcap2series converter.

        @param pcap2series: a pcap to a pandas converter 
        @param number_of_packets: number of packets to read from this file
        @param filepath: the path to the file to read from 
        @returns: the corresponding pandas dataframe
        '''
        
        # just in case anybody tries
        if number_of_packets <= 0:
            raise Exception("Nprint has a bug when reading 0 packets (reads everything)")

        # set the number of packets to read and read them
        pcap2series.set_read_packets(number_of_packets)
        return pcap2series.pcap_to_object(filepath)

    def _fill_nans(self, dataframe: pd.DataFrame) -> None:
        '''
        _fill_nans exists due to a small bug in the nprint code, an off by one error that makes the icmp_rho_31
        go missing every now and then. Just fills NaNs with -1

        @param dataframe: the dataframe to fill nans
        '''
        
        #! Another bug i found in nprint. Sometimes, the bit for icmp_rho_31 goes missing (instead of 0,-1,1 is NaN), Fill nans with -1
        cols_with_nans = dataframe.columns[dataframe.isna().any()].tolist()
        for col in cols_with_nans:
            try:
                dataframe[col] = dataframe[col].fillna(-1).astype('int64')
            except:
                print(f"Will not convert column {col}")

    def _write_processed_dataframe(self, target_file: str, dataframe: pd.DataFrame) -> None:
        '''
        _write_processed_dataframe will write the dataframe to a specified location, appending the result
        in the case the file exists

        @param target_file: the path of the file to write to.
        @param dataframe: the dataframe to write.
        '''
        
        # create the file if it does not exist and otherwise append
        if not os.path.exists(target_file):
            dataframe.to_csv(target_file,mode='a',index=False)
        else:
            dataframe.to_csv(target_file,mode='a',index=False,header=False)
        
    def run(self) -> None:
        target_csv = self._configuration_template.output_file

        # if target csv exists, delete it 
        if os.path.exists(target_csv):
            os.remove(target_csv)

        source_file = self._configuration_template.input_file
        number_to_process = self._configuration_template.packets_to_read

        #! THERE IS A BUG IN NPRINT WHEN number_processed IS 0 (prints everything)
        if number_to_process != 0:
            if number_to_process != 'max' and number_to_process < 0:
                raise Exception("packets_to_read must be 'max' or a positive number")
            # -c is only given to nPrint when a limit was asked for: counting the packets first meant
            # loading the whole file in memory (and dpkt cannot read pcapng).
            self._pcap2series_converter.set_read_packets(number_to_process)

            # dataframe = self._drop_extra_packets(
            #     dataframe,
            #     self._configuration_template.instances_per_series
            # )

            # new_max = self._add_series_identifier(
            #     dataframe,
            #     self._configuration_template.instances_per_series,
            #     series_identifier
            # )
            # series_identifier = new_max + 1

            # dataframe['instance_id'] = dataframe.index

            # # add the type of the instance
            # for configured_attack in self._configuration_template.ruleset.values():
            #     if configured_attack == attack_type:
            #         dataframe['type_' + configured_attack] = 1.0
            #     else:
            #         dataframe['type_' + configured_attack] = 0.0

            for dataframe in self._pcap2series_converter.pcap_to_chunks(source_file, NPRINT_CHUNK_ROWS):
                self._fill_nans(dataframe)
                self._write_processed_dataframe(target_csv, dataframe)


def number_of_packets(path: str) -> int:
    '''
    number_of_packets returns the number of packets within a pcap file

    @param path: the path to the pcap file
    @returns: the number of packets within that file
    '''

    import dpkt   # only needed here, and only reads classic .pcap files

    with open(path, 'rb') as f:
        pcap_reader = dpkt.pcap.Reader(f)    
        # pcaps have little metadata inside, to get this the only way is reading the packets themselves
        return sum(1 for _ in pcap_reader)

if __name__ == '__main__':

    # When the batch runner stops this process (SIGTERM), exit normally so that nPrint is stopped too
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(143))

    # Crear el parser
    parser = argparse.ArgumentParser(description="Processing of a single PCAP file into a CSV consumable by ML models.")

    # Definir los argumentos
    parser.add_argument(
        "pcap_file",
        type=str,
        help="path of the PCAP file to process"
    )

    parser.add_argument(
        '--headers',
        nargs='+',
        default=[],
        help='List of headers to include',
        choices=['ethernet', 'ipv4', 'ipv6', 'absolute_time', 'icmp', 'tcp', 'udp', 'relative_time', 'arp']
    )

    parser.add_argument(
        '--masks',
        nargs='+',
        default=[],
        help='List of headers from which to elimiate location information',
        choices= ['ethernet', 'arp', 'ipv4', 'ipv6', 'tcp', 'udp', 'ip', 'icmp']
    )

    parser.add_argument(
        '--output_csv',
        type=str,
        default=None,
        help='path of the output CSV (default: <pcap_file>.csv)'
    )

    args = parser.parse_args()

    exectuion_configuration = SinglePcapConfigTemplate(
        args.headers,
        'prefix_delete',
        args.masks,
        args.pcap_file,
        args.output_csv or args.pcap_file + '.csv'
    )

    pipeline = SinglePcapPipeline(
        exectuion_configuration
    )

    pipeline.run()
