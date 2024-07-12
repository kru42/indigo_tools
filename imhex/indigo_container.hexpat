#pragma description Quantic Dream container format

import std.core;
import std.io;

enum ContainerType : u64 {
    COM_CONT = 0x544E4F435F4D4F43,  // COM_CONT
    PARTITIO = 0x4F49544954524150,  // PARTITIO
    DATABANK = 0x4B4E414241544144,  // DATABANK (no metadata section)
    DBANKIDX = 0x5844494B4E414244   // DBANKIDX
};

struct ComContMetadata {
    u8 key1[8];
    u8 unk1[12];
    
    u8 key2[8];
    u8 unk2[8];
    
    u8 key3[8];
    u8 unk3[12];
    
    u32 entries_num [[color("0000FF")]];
};

struct PartitioMetadata {
    u8 key1[8];
    u32 unk[6];
    
    u8 key2[8];
    u32 unk2[5];
    
    u8 key3[8];
    u32 unk3[7];
    
    u8 unk4;
};

struct ComContEntry {
    u32 unk1 [[color("FF0000")]];
    u32 id1;
    
    u32 unk2;
    u32 id2;
};

struct ContainerFile {
    ContainerType type;
    u32 unk1;   // unknown, 1 or 2  
      
    u32 data_size;
    padding[data_size];
    
    match (type) {
        (ContainerType::COM_CONT): ComContMetadata metadata;
        (ContainerType::PARTITIO): PartitioMetadata metadata;
    }
};


ContainerFile containerFile @ 0x00;