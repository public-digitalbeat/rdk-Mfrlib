#ifndef __IMGHEAD_H__
#define __IMGHEAD_H__

typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;

//static const int NAME_SIZE_V2	= 0x100L;
#define NAME_SIZE_V2  0x100L
static const int RW_MAX_SIZE   	= 0x40000L;
static const int VERSION_V2	= 0x2L;
static const int IMAGE_MAGIC	= 0x27b51956L;

#define  MAX_PARTITIONS    (32)

static const int IMAGE_ITEM_TYPE_NORMAL	= 0x0L;
static const int IMAGE_ITEM_TYPE_SPARSE	= 0xFEL;

#pragma pack(push,4)
typedef struct _VERSION_HEAD
{
	__u32		crc;	//check sum of the image
	__u32		version;	//firmware version
}VERSION_HEAD;

#define RESERVE_INF_SZ 36
typedef struct _AmlFirmwareImg_s
{
	VERSION_HEAD verh;
	__u32      magic;           //magic No. to say it is Amlogic firmware image
	__u64      imageSz;         //total size of this image file
	__u32      itemAlginSize;   //align size for each item
	__u32      itemNum;         //item number in the image, each item a file
	char       reserve[RESERVE_INF_SZ];
}IMG_HEAD;

//UserInfo_t next to IMG_HEAD
typedef struct {
    char    info[512];
}UserInfo_t;


typedef struct _AmlFirmwareImg_V2_s
{
	__u32			itemId;
	__u32			fileType;				//image file type, sparse and normal
	__u64			curoffsetInItem;    //current offset in the item
	__u64			offsetInImage;      //item offset in the image
	__u64			itemSz;					//item size in the image
	char			itemMainType[NAME_SIZE_V2];   //item main type and sub type used to index the item
	char			itemSubType[NAME_SIZE_V2];    //item main type and sub type used to index the item
	__u32			verify;
	__u16			isBackUpItem;        //this item source file is the same as backItemId
	__u16			backUpItemId;        //if 'isBackUpItem', then this is the item id
	char			reserve[24];
}ITEMINFO_V2;

#ifndef _MAX_FNAME
#define _MAX_FNAME 256
#endif// #ifndef _MAX_FNAME

typedef struct _AmlItemMap_s
{
	ITEMINFO_V2     itemv2;
	char		    srcfilename[_MAX_FNAME];
    int             isVerifyItem;//[Added by Sam]is this item the verify item
}MAPITEM;

#pragma pack(pop)
#endif
