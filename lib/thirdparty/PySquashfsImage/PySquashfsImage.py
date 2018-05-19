#!/usr/bin/env python

# -*- coding: utf-8 -*-

"""
This module is released with the LGPL license.
Copyright 2011-2012

Matteo Mattei <matteo.mattei@gmail.com>
Nicola Ponzeveroni <nicola.ponzeveroni@gilbarco.com>

It is intended to be used to access files into a SQUASHFS 4.0 image file.

Based on Phillip Lougher <phillip@lougher.demon.co.uk> Unsquash tool
"""
__all__ = ['SquashFsImage','SquashedFile','SquashInode']

import sys
import stat

SQUASHFS_CHECK = 2

SQUASHFS_UIDS           = 256
SQUASHFS_GUIDS          = 255

ZLIB_COMPRESSION        = 1
LZMA_COMPRESSION        = 2
LZO_COMPRESSION         = 3
XZ_COMPRESSION          = 4
LZ4_COMPRESSION         = 5

SQUASHFS_MAJOR          = 4
SQUASHFS_MINOR          = 0
SQUASHFS_MAGIC          = 0x73717368
SQUASHFS_START          = 0

SQUASHFS_METADATA_SIZE  = 8192
SQUASHFS_METADATA_LOG   = 13

FRAGMENT_BUFFER_DEFAULT = 256
DATA_BUFFER_DEFAULT     = 256

SQUASHFS_NAME_LEN      = 256
SQUASHFS_INVALID       = 0xffffffffffff
SQUASHFS_INVALID_FRAG  = 0xffffffff
SQUASHFS_INVALID_XATTR = 0xffffffff
SQUASHFS_INVALID_BLK   = 0xFFFFFFFFFFFFFFFF #-1
SQUASHFS_USED_BLK      = SQUASHFS_INVALID_BLK-1 #-2

SQUASHFS_DIR_TYPE      =  1
SQUASHFS_FILE_TYPE     =  2
SQUASHFS_SYMLINK_TYPE  =  3
SQUASHFS_BLKDEV_TYPE   =  4
SQUASHFS_CHRDEV_TYPE   =  5
SQUASHFS_FIFO_TYPE     =  6
SQUASHFS_SOCKET_TYPE   =  7
SQUASHFS_LDIR_TYPE     =  8
SQUASHFS_LREG_TYPE     =  9
SQUASHFS_LSYMLINK_TYPE = 10
SQUASHFS_LBLKDEV_TYPE  = 11
SQUASHFS_LCHRDEV_TYPE  = 12
SQUASHFS_LFIFO_TYPE    = 13
SQUASHFS_LSOCKET_TYPE  = 14


#****** MACROS
SQUASHFS_COMPRESSED_BIT = (1 << 15)
SQUASHFS_COMPRESSED_BIT_BLOCK =	(1 << 24)

def SQUASHFS_COMPRESSED_SIZE(B): 
	if ((B) & ~SQUASHFS_COMPRESSED_BIT):
		return  (B) & ~SQUASHFS_COMPRESSED_BIT   
	else:
		return SQUASHFS_COMPRESSED_BIT

def SQUASHFS_BIT(flag, bit): return (((flag >> bit) & 1)!=0)
def SQUASHFS_CHECK_DATA(flags): return SQUASHFS_BIT(flags, SQUASHFS_CHECK)
def SQUASHFS_COMPRESSED(B): return (((B) & SQUASHFS_COMPRESSED_BIT) == 0)
def SQUASHFS_COMPRESSED_SIZE_BLOCK(B): return 	((B) & ~SQUASHFS_COMPRESSED_BIT_BLOCK)
def SQUASHFS_COMPRESSED_BLOCK(B): return (((B) & SQUASHFS_COMPRESSED_BIT_BLOCK) == 0)
def SQUASHFS_INODE_BLK(a): return (((a) >> 16)&0xFFFFFFFF)
def SQUASHFS_INODE_OFFSET(a): return (((a) & 0xffff))
def SQUASHFS_MKINODE(A, B): return  ((((A) << 16) + (B))&0xFFFFFFFFFFFFFFFF)
def SQUASHFS_MK_VFS_INODE(a, b): return	((((a) << 8) + ((b) >> 2) + 1)&0xFFFFFFFF)
def SQUASHFS_MODE(a): return	((a) & 0xfff)
def SQUASHFS_FRAGMENT_BYTES(A): return 	((A) * 16)
def SQUASHFS_FRAGMENT_INDEX(A): return (SQUASHFS_FRAGMENT_BYTES(A) // SQUASHFS_METADATA_SIZE)
def SQUASHFS_FRAGMENT_INDEX_OFFSET(A): return	(SQUASHFS_FRAGMENT_BYTES(A) % SQUASHFS_METADATA_SIZE)
def SQUASHFS_FRAGMENT_INDEXES(A): return ((SQUASHFS_FRAGMENT_BYTES(A) + SQUASHFS_METADATA_SIZE - 1) // SQUASHFS_METADATA_SIZE)
def SQUASHFS_FRAGMENT_INDEX_BYTES(A): return (SQUASHFS_FRAGMENT_INDEXES(A) * 8)
def SQUASHFS_LOOKUP_BYTES(A): return	((A) * 8)
def SQUASHFS_LOOKUP_BLOCK(A): return	(SQUASHFS_LOOKUP_BYTES(A) // SQUASHFS_METADATA_SIZE)
def SQUASHFS_LOOKUP_BLOCK_OFFSET(A): return	(SQUASHFS_LOOKUP_BYTES(A) % SQUASHFS_METADATA_SIZE)
def SQUASHFS_LOOKUP_BLOCKS(A): return	((SQUASHFS_LOOKUP_BYTES(A) + SQUASHFS_METADATA_SIZE - 1) // SQUASHFS_METADATA_SIZE)
def SQUASHFS_LOOKUP_BLOCK_BYTES(A): return (SQUASHFS_LOOKUP_BLOCKS(A) * 8)
def SQUASHFS_ID_BYTES(A): return ((A) * 4)
def SQUASHFS_ID_BLOCK(A): return (SQUASHFS_ID_BYTES(A) // SQUASHFS_METADATA_SIZE)
def SQUASHFS_ID_BLOCK_OFFSET(A): return	(SQUASHFS_ID_BYTES(A) % SQUASHFS_METADATA_SIZE)
def SQUASHFS_ID_BLOCKS(A): return ((SQUASHFS_ID_BYTES(A) + SQUASHFS_METADATA_SIZE - 1) // SQUASHFS_METADATA_SIZE)
def SQUASHFS_ID_BLOCK_BYTES(A): return	(SQUASHFS_ID_BLOCKS(A) * 8)
def SQUASHFS_XATTR_BYTES(A): return ((A) * 16)
def SQUASHFS_XATTR_BLOCK(A): return (SQUASHFS_XATTR_BYTES(A) // SQUASHFS_METADATA_SIZE)
def SQUASHFS_XATTR_BLOCK_OFFSET(A): return (SQUASHFS_XATTR_BYTES(A) % SQUASHFS_METADATA_SIZE)
def SQUASHFS_XATTR_BLOCKS(A):return ((SQUASHFS_XATTR_BYTES(A) + SQUASHFS_METADATA_SIZE - 1) // SQUASHFS_METADATA_SIZE)
def SQUASHFS_XATTR_BLOCK_BYTES(A): return (SQUASHFS_XATTR_BLOCKS(A) * 8)
def SQUASHFS_XATTR_BLK(A): return ( ((A) >> 16)&0xFFFFFFFF)
def SQUASHFS_XATTR_OFFSET(A): return (((A) & 0xffff))


SQASHFS_LOOKUP_TYPE= [
		0,
		stat.S_IFDIR,
		stat.S_IFREG,
		stat.S_IFLNK,
		stat.S_IFBLK,
		stat.S_IFCHR,
		stat.S_IFIFO,
		stat.S_IFSOCK,
		stat.S_IFDIR,
		stat.S_IFREG,
		stat.S_IFLNK,
		stat.S_IFBLK,
		stat.S_IFCHR,
		stat.S_IFIFO,
		stat.S_IFSOCK]


def str2byt(data):
	if type( data ) == str:
		return data.encode("latin-1")
	return data

def byt2str(data):
	if type( data ) == bytes:
		return data.decode("latin-1")
	return data

class _Compressor:
	def __init__(self):
		self.supported = 0
		self.name="none"

	def uncompress(self, src):
		return src

class _ZlibCompressor:
	def __init__(self):
		self.supported = ZLIB_COMPRESSION
		self.name="zlib"
		
	def uncompress(self, src):
		import zlib
		return zlib.decompress(src)

class _XZCompressor:
	def __init__(self):
		self.supported = XZ_COMPRESSION
		self.name="xz"
		
	def uncompress(self, src):
            try:
                import lzma
            except ImportError:
                from backports import lzma
            return lzma.decompress(src)

_compressors = ( _Compressor(), _ZlibCompressor(), _XZCompressor() )

if sys.version_info[0] < 3: pyVersionTwo = True
else: pyVersionTwo = False

class _Squashfs_commons():
	def makeInteger(self,myfile,length):
		""" Assemble multibyte integer """
		ret = 0
		pwr = 1
		for i in range(0,length):
			ret += ((ord(myfile.read(1))&0xFF)*pwr)
			pwr *= 0x100
		return ret

	def readShort(self,myfile):
		return self.makeInteger(myfile,2)

	def readInt(self,myfile):
		return self.makeInteger(myfile,4)

	def readLong(self,myfile):
		return self.makeInteger(myfile,8)
		
	def makeBufInteger(self,buf,start,lenght):
		""" Assemble multibyte integer """
		ret = 0
		pwr = 1
		for i in range(start,start+lenght):
			if pyVersionTwo:
				ret += ((ord(buf[i])&0xFF)*pwr)
			else:
				ret += ((int(buf[i])&0xFF)*pwr)
			pwr *= 0x100
		return ret
		
	def autoMakeBufInteger(self,buf,start,length):
		""" Assemble multibyte integer """
		return (self.makeBufInteger(buf,start,length), start+length)

class _Squashfs_super_block(_Squashfs_commons):
	def __init__(self):
		self.s_magic = 0
		self.inodes = 0
		self.mkfs_time = 0
		self.block_size = 0
		self.fragments = 0
		self.compression = 0
		self.block_log = 0
		self.flags = 0
		self.no_ids = 0
		self.s_major = 0
		self.s_minor = 0
		self.root_inode = 0
		self.bytes_used = 0
		self.id_table_start = 0
		self.xattr_id_table_start = 0
		self.inode_table_start = 0
		self.directory_table_start = 0
		self.fragment_table_start = 0
		self.lookup_table_start = 0

	def read(self,myfile):
		self.s_magic = self.readInt(myfile)
		self.inodes = self.readInt(myfile)
		self.mkfs_time = self.readInt(myfile)
		self.block_size = self.readInt(myfile)
		self.fragments = self.readInt(myfile)
		self.compression = self.readShort(myfile)
		self.block_log = self.readShort(myfile)
		self.flags = self.readShort(myfile)
		self.no_ids = self.readShort(myfile)
		self.s_major = self.readShort(myfile)
		self.s_minor = self.readShort(myfile)
		self.root_inode = self.readLong(myfile)
		self.bytes_used = self.readLong(myfile)
		self.id_table_start = self.readLong(myfile)
		self.xattr_id_table_start = self.readLong(myfile)
		self.inode_table_start = self.readLong(myfile)
		self.directory_table_start = self.readLong(myfile)
		self.fragment_table_start = self.readLong(myfile)
		self.lookup_table_start = self.readLong(myfile)

class _Squashfs_fragment_entry(_Squashfs_commons): 
	def __init__(self):
		self.start_block=0
		self.size=0
		self.unused=0
		self.fragment = None
	def read(self,myfile):
		self.start_block=self.readLong(myfile)
		self.size=self.readInt(myfile)
		self.unused=self.readInt(myfile)
	def fill(self,block,ofs):
		self.start_block,ofs=self.autoMakeBufInteger(block,ofs,8)
		self.size       ,ofs=self.autoMakeBufInteger(block,ofs,4)
		self.unused     ,ofs=self.autoMakeBufInteger(block,ofs,4)
		return ofs

class SquashInode:
	def __init__(self,owner_image):
		self.image = owner_image
		self.blocks = 0
		self.block_ptr = 0
		self.data = 0  
		self.fragment = 0
		self.frag_bytes = 0
		self.gid=0
		self.inode_number = 0
		self.mode = 0
		self.offset = 0
		self.start = 0
		self.symlink = 0
		self.time = 0
		self.type = 0
		self.uid = 0
		self.sparse = 0
		self.xattr = 0
		
	def getContent(self):
		return self.image.getFileContent(self)
	
	def hasAttribute(self,mask):
		return (self.mode & mask)==mask
		
class _Inode_header(_Squashfs_commons):
	def __init__(self):
		self.inode_type =0
		self.mode=0
		self.uid=0
		self.guid=0
		self.mtime=0
		self.inode_number=0

		self.rdev=0
		self.xattr=0

		self.nlink=0
		self.symlink_size=0
		self.symlink=[]

		self.start_block=0
		self.fragment=0

		self.block_list=[]
		self.file_size=0
		self.offset=0
		self.parent_inode=0
		self.start_block=0
		self.file_size=0
		self.i_count=0
		self.offset=0

		self.file_size=0
		self.sparse=0
		self.index= []

	def base_header(self,buff,offset):
		self.inode_type,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mode,offset = self.autoMakeBufInteger(buff,offset,2)
		self.uid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.guid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mtime,offset = self.autoMakeBufInteger(buff,offset,4)
		self.inode_number,offset = self.autoMakeBufInteger(buff,offset,4)
		return offset

	def ipc_header(self,buff,offset):
		self.inode_type,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mode,offset = self.autoMakeBufInteger(buff,offset,2)
		self.uid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.guid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mtime,offset = self.autoMakeBufInteger(buff,offset,4)
		self.inode_number,offset = self.autoMakeBufInteger(buff,offset,4)
		self.nlink,offset = self.autoMakeBufInteger(buff,offset,4)
		return offset
		
	def lipc_header(self,buff,offset):
		self.inode_type,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mode,offset = self.autoMakeBufInteger(buff,offset,2)
		self.uid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.guid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mtime,offset = self.autoMakeBufInteger(buff,offset,4)
		self.inode_number,offset = self.autoMakeBufInteger(buff,offset,4)
		self.nlink,offset = self.autoMakeBufInteger(buff,offset,4)
		self.xattr,offset = self.autoMakeBufInteger(buff,offset,4)
		return offset

	def dev_header(self,buff,offset):
		self.inode_type,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mode,offset = self.autoMakeBufInteger(buff,offset,2)
		self.uid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.guid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mtime,offset = self.autoMakeBufInteger(buff,offset,4)
		self.inode_number,offset = self.autoMakeBufInteger(buff,offset,4)
		self.nlink,offset = self.autoMakeBufInteger(buff,offset,4)
		self.rdev,offset = self.autoMakeBufInteger(buff,offset,4)
		return offset
		
	def ldev_header(self,buff,offset):
		self.inode_type,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mode,offset = self.autoMakeBufInteger(buff,offset,2)
		self.uid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.guid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mtime,offset = self.autoMakeBufInteger(buff,offset,2)
		self.inode_number,offset = self.autoMakeBufInteger(buff,offset,2)
		self.nlink,offset = self.autoMakeBufInteger(buff,offset,2)
		self.rdev,offset = self.autoMakeBufInteger(buff,offset,2)
		self.xattr,offset = self.autoMakeBufInteger(buff,offset,2)
		return offset
	    
	def symlink_header(self,buff,offset):
		self.inode_type,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mode,offset = self.autoMakeBufInteger(buff,offset,2)
		self.uid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.guid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mtime,offset = self.autoMakeBufInteger(buff,offset,4)
		self.inode_number,offset = self.autoMakeBufInteger(buff,offset,4)
		self.nlink,offset = self.autoMakeBufInteger(buff,offset,4)
		self.symlink_size,offset = self.autoMakeBufInteger(buff,offset,4)
		self.symlink=buff[offset:]
		return offset

	def reg_header (self,buff,offset):
		self.inode_type,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mode,offset = self.autoMakeBufInteger(buff,offset,2)
		self.uid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.guid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mtime,offset = self.autoMakeBufInteger(buff,offset,4)
		self.inode_number,offset = self.autoMakeBufInteger(buff,offset,4)
		self.start_block,offset = self.autoMakeBufInteger(buff,offset,4)
		self.fragment,offset = self.autoMakeBufInteger(buff,offset,4)
		self.offset,offset = self.autoMakeBufInteger(buff,offset,4)
		self.file_size,offset = self.autoMakeBufInteger(buff,offset,4)
		self.block_list=buff[offset:]
		return offset

	def lreg_header (self,buff,offset):
		self.inode_type,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mode,offset = self.autoMakeBufInteger(buff,offset,2)
		self.uid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.guid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mtime,offset = self.autoMakeBufInteger(buff,offset,4)
		self.inode_number,offset = self.autoMakeBufInteger(buff,offset,4)
		self.start_block,offset = self.autoMakeBufInteger(buff,offset,8)
		self.file_size,offset = self.autoMakeBufInteger(buff,offset,8)
		self.sparse,offset = self.autoMakeBufInteger(buff,offset,8)
		self.nlink,offset = self.autoMakeBufInteger(buff,offset,4)
		self.fragment,offset = self.autoMakeBufInteger(buff,offset,4)
		self.offset,offset = self.autoMakeBufInteger(buff,offset,4)
		self.xattr,offset = self.autoMakeBufInteger(buff,offset,4)
		self.block_list,offset = self.autoMakeBufInteger(buff,offset,4)
		return offset

	def dir_header (self,buff,offset):
		self.inode_type,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mode,offset = self.autoMakeBufInteger(buff,offset,2)
		self.uid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.guid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mtime,offset = self.autoMakeBufInteger(buff,offset,4)
		self.inode_number,offset = self.autoMakeBufInteger(buff,offset,4)
		self.start_block,offset = self.autoMakeBufInteger(buff,offset,4)
		self.nlink,offset = self.autoMakeBufInteger(buff,offset,4)
		self.file_size,offset = self.autoMakeBufInteger(buff,offset,2)
		self.offset,offset = self.autoMakeBufInteger(buff,offset,2)
		self.parent_inode,offset = self.autoMakeBufInteger(buff,offset,4)
		return offset

	def ldir_header (self,buff,offset):
		self.inode_type,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mode,offset = self.autoMakeBufInteger(buff,offset,2)
		self.uid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.guid,offset = self.autoMakeBufInteger(buff,offset,2)
		self.mtime,offset = self.autoMakeBufInteger(buff,offset,4)
		self.inode_number,offset = self.autoMakeBufInteger(buff,offset,4)
		self.nlink,offset = self.autoMakeBufInteger(buff,offset,4)
		self.file_size,offset = self.autoMakeBufInteger(buff,offset,4)
		self.start_block,offset = self.autoMakeBufInteger(buff,offset,4)
		self.parent_inode,offset = self.autoMakeBufInteger(buff,offset,4)
		self.i_count,offset = self.autoMakeBufInteger(buff,offset,2)
		self.offset,offset = self.autoMakeBufInteger(buff,offset,2)
		self.xattr,offset = self.autoMakeBufInteger(buff,offset,4)
		self.index = buff[offset:]
		return offset


class _Dir_entry(_Squashfs_commons):     
	def __init__(self):
		self.offset=0
		self.inode_number=0
		self.type=0
		self.size=0
		self.name=[]
		self.s_file = None
	
	def fill(self,buffer,ofs):
		self.offset,ofs=self.autoMakeBufInteger(buffer,ofs,2)
		self.inode_number,ofs=self.autoMakeBufInteger(buffer,ofs,2)
		self.type,ofs=self.autoMakeBufInteger(buffer,ofs,2)
		self.size,ofs=self.autoMakeBufInteger(buffer,ofs,2)
		self.name=buffer[ofs:ofs+self.size]
		
class _Dir_header(_Squashfs_commons):
	def __init__(self):
		self.count=0
		self.start_block=0
		self.inode_number=0
	def fill(self,buffer,ofs):
		self.count,ofs=self.autoMakeBufInteger(buffer,ofs,4)
		self.start_block,ofs=self.autoMakeBufInteger(buffer,ofs,4)
		self.inode_number,ofs=self.autoMakeBufInteger(buffer,ofs,4)

class _Dir: 
	def __init__(self):
		self.dir_count=0
		self.cur_entry=0
		self.mode=0
		self.uid=0
		self.guid=0
		self.mtime=0
		self.xattr=0
		self.dirs=[]

class _Xattr_id(_Squashfs_commons): # 16
	def __init__(self):
		self.xattr = 0
		self.count = 0
		self.size = 0

	def fill(self,buffer,ofs):
		self.xattr,ofs=self.autoMakeBufInteger(buffer,ofs,8)
		self.count,ofs=self.autoMakeBufInteger(buffer,ofs,4)
		self.size,ofs=self.autoMakeBufInteger(buffer,ofs,4)

class _Xattr_table(_Squashfs_commons):
	def __init__(self):
		self.xattr_table_start = 0
		self.xattr_ids = 0
		self.unused = 0

	def read(self,myfile):
		self.xattr_table_start = self.readLong(myfile)
		self.xattr_ids = self.readInt(myfile)
		self.unused = self.readInt(myfile)

class SquashedFile():
	def __init__(self, name, parent):
	      self.name = name
	      self.children = []
	      self.inode = None
	      self.parent = parent
	      
	def getPath(self) :
		if self.parent == None:
			return self.name
		else:
			return self.parent.getPath() + "/" + byt2str(self.name)
			
	def findAll(self):
		ret = [ self ]
		for i in self.children :
			ret += i.findAll()
		return ret 
			
	def findAllPaths(self):
		ret = [ self.getPath() ]
		for i in self.children :
			ret += i.findAllPaths()
		return ret 
		
	def getContent( self ):
		if self.inode==None:
			return None
		return self.inode.getContent()
		
	def read(self,path):
		node = self.select(path)
		if node==None:
			return None
		return node.getContent()

	def dirlist(self,path):
		node = self.select(path)
		if node==None:
			return None
		return node.children

	def select(self,path):
		if path == str2byt("/"):
			path = str2byt("")
		lpath = path.split(str2byt("/"))
		start = self
		ofs = 0
		if  lpath[0] == str2byt(""):
			ofs = 1
			while start.parent!=None:
				start = start.parent
		if ofs>=len(lpath):
			return start
		for child in start.children :
			if child.name == lpath[ofs] :
				return child._lselect( lpath, ofs + 1 )
		return None

	def _lselect(self, lpath, ofs ):
		#print lpath,self.name,ofs
		if ofs>=len(lpath):
			return self
		for child in self.children :
			if child.name == lpath[ofs] :
				return child._lselect( lpath, ofs+1 )
		return None

	def hasAttribute(self,mask):
		if self.inode==None:
			return False
		return self.inode.hasAttribute(mask)
		
	def  isFolder(self):
		if self.parent==None : 
			return True
		return self.hasAttribute(stat.S_IFDIR)	
		
	def close(self):	
		self.inode.image.close()
	def getLength(self):
		return self.inode.data
		
	def getName(self):
		return self.name
		

class SquashFsImage(_Squashfs_commons):
	def __init__(self,filepath=None,offset=None):
		self.comp = None
		self.sBlk = _Squashfs_super_block()
		self.fragment_buffer_size = FRAGMENT_BUFFER_DEFAULT
		self.data_buffer_size = DATA_BUFFER_DEFAULT
		self.block_size = 0
		self.block_log = 0
		self.all_buffers_size = 0
		self.fragment_table = []
		self.id_table = 0
		self.inode_table_hash = {}
		self.inode_table = str2byt("")
		self.id_table = []
		self.hash_table = {}
		self.xattrs = b""
		self.directory_table_hash={}
		self.created_inode = []
		self.total_blocks = 0
		self.total_files = 0
		self.total_inodes = 0
		self.directory_table = str2byt('')
		self.inode_to_file = {}
		self.root = SquashedFile("",None) 
		self.image_file = None
		self.offset = int(offset) if offset else 0
		if( filepath!=None ):
			self.open(filepath)

	def getRoot(self):
		return self.root

	def setFile(self,fd):
		self.image_file=fd
		fd.seek(self.offset)
		self.initialize(self.image_file)

	def open(self,filepath):
		self.image_file = open(filepath,'rb')
		self.image_file.seek(self.offset)
		self.initialize(self.image_file)
		
	def close(self):
		self.image_file.close()

	def __read_super(self,fd):
		self.sBlk.read(fd)
		if self.sBlk.s_magic != SQUASHFS_MAGIC or self.sBlk.s_major != 4 or self.sBlk.s_minor != 0:
			raise IOError("The file supplied is not a squashfs 4.0 image")
		self.comp = self.getCompressor(self.sBlk.compression)

	def getCompressor(self,compression_id):
		for c in _compressors :
			if c.supported == compression_id :
				return c
		raise ValueError( "Unknown compression method "+compression_id )

	def initialize(self,myfile):
		self.__read_super(myfile)
		self.created_inode = [ None for i in range(0,self.sBlk.inodes) ]
		self.block_size           = self.sBlk.block_size
		self.block_log            = self.sBlk.block_log
		self.fragment_buffer_size <<= 20 - self.block_log
		self.data_buffer_size     <<= 20 - self.block_log
		self.all_buffers_size     = self.fragment_buffer_size + self.data_buffer_size
		self.read_uids_guids(myfile)
		self.read_fragment_table(myfile)
		self.uncompress_inode_table(myfile,self.sBlk.inode_table_start,self.sBlk.directory_table_start)
		self.uncompress_directory_table(myfile,self.sBlk.directory_table_start,self.sBlk.fragment_table_start)
		self.read_xattrs_from_disk(myfile)
		root_block = SQUASHFS_INODE_BLK   (self.sBlk.root_inode)
		root_offs  = SQUASHFS_INODE_OFFSET(self.sBlk.root_inode)
		self.pre_scan("squashfs-root",root_block,root_offs, self.root)

	def read_data_block(self, myfile, start, size):
		c_byte = SQUASHFS_COMPRESSED_SIZE_BLOCK(size)
		myfile.seek(self.offset + start)
		data = myfile.read(c_byte)
		if(SQUASHFS_COMPRESSED_BLOCK(size)) :
			return self.comp.uncompress(data)
		else :
			return data

	def getFileContent(self,inode):
		start = inode.start
		content = str2byt("")
		block_list = self.read_block_list(inode)
		for cur_blk in block_list :
			if cur_blk == SQUASHFS_INVALID_FRAG:
				continue
			c_byte = SQUASHFS_COMPRESSED_SIZE_BLOCK(cur_blk)
			if cur_blk != 0: # non sparse file 
				buffer = self.read_data_block(self.image_file,start,cur_blk)
				content +=buffer
				start   += c_byte
		if inode.frag_bytes !=0  :
			start, size = self.read_fragment(inode.fragment)
			buffer = self.read_data_block(self.image_file,start,size)
			content += buffer[inode.offset:inode.offset+inode.frag_bytes] # inode.frag_bytes was (inode.data%self.block_size)
		return content

	def read_block_list(self,inode):
		ret = []
		ofs = inode.block_ptr
		for i in range(0,inode.blocks):
			number,ofs = self.autoMakeBufInteger(self.inode_table,ofs,4)
			ret.append(number)
		return ret	

	def read_block(self,myfile,start):
		myfile.seek(self.offset + start,0)
		c_byte = self.readShort(myfile)
		offset = 2
		if SQUASHFS_CHECK_DATA(self.sBlk.flags) :
			offset = 3
		if SQUASHFS_COMPRESSED(c_byte) : 
			myfile.seek(self.offset + start + offset)
			c_byte = SQUASHFS_COMPRESSED_SIZE(c_byte)
			buffer = myfile.read(c_byte)
			block  = self.comp.uncompress(buffer)
			return (block,start + offset + c_byte, c_byte)
		else: 
			myfile.seek(self.offset + start + offset)
			c_byte = SQUASHFS_COMPRESSED_SIZE(c_byte)
			block  = myfile.read(c_byte)
			return (block, start + offset + c_byte, c_byte)

	def uncompress_inode_table(self,myfile,start,end):
		bytes = 0
		while start < end :
			self.inode_table_hash[start] = bytes
			block,start,res = self.read_block(myfile, start)
			self.inode_table += block
			bytes=len(self.inode_table)

	def read_fragment_table(self,myfile):
		indexes = SQUASHFS_FRAGMENT_INDEXES(self.sBlk.fragments)
		fragment_table_index = [None for i in range(0,indexes)]
		self.fragment_table  = []
		if self.sBlk.fragments == 0:
			return True
		myfile.seek(self.offset + self.sBlk.fragment_table_start)
		for i in range(0,indexes) :
			fragment_table_index[i] = self.readLong(myfile)
		table = str2byt("")
		for i in range(0,indexes): 
			 block = self.read_block(myfile, fragment_table_index[i])[0]
			 table += block
		ofs = 0	 
		while ofs<len(table) :
			entry = _Squashfs_fragment_entry()
			ofs = entry.fill(table,ofs)
			entry.fragment = self.read_data_block(myfile,entry.start_block,entry.size)
			self.fragment_table.append(entry)
			
	def read_fragment(self,fragment):
		entry = self.fragment_table[fragment]
		return ( entry.start_block, entry.size )

	def read_inode(self,start_block,offset):
		start = self.sBlk.inode_table_start + start_block
		bytes = self.inode_table_hash[start]
		block_ptr = bytes + offset
		i = SquashInode(self)
		header = _Inode_header()
		header.base_header(self.inode_table,block_ptr)
		i.uid  = self.id_table[header.uid]
		i.gid  = self.id_table[header.guid]
		i.mode = SQASHFS_LOOKUP_TYPE[header.inode_type] | header.mode
		i.type = header.inode_type
		i.time = header.mtime
		i.inode_number = header.inode_number
		if header.inode_type==SQUASHFS_DIR_TYPE :
			header.dir_header(self.inode_table,block_ptr)
			i.data   = header.file_size
			i.offset = header.offset
			i.start  = header.start_block
			i.xattr  = SQUASHFS_INVALID_XATTR
		elif header.inode_type==SQUASHFS_LDIR_TYPE: 
			header.ldir_header(self.inode_table,block_ptr)
			i.data   = header.file_size
			i.offset = header.offset
			i.start  = header.start_block
			i.xattr  = header.xattr
		elif header.inode_type==SQUASHFS_FILE_TYPE: 
			i.block_ptr = header.reg_header(self.inode_table,block_ptr)
			i.data = header.file_size
			if header.fragment == SQUASHFS_INVALID_FRAG:
				i.frag_bytes = 0
			else:
				i.frag_bytes = header.file_size % self.sBlk.block_size
			i.fragment = header.fragment
			i.offset = header.offset
			if header.fragment == SQUASHFS_INVALID_FRAG:
				i.blocks = (i.data + self.sBlk.block_size - 1) >> self.sBlk.block_log
			else:
				i.blocks = i.data >> self.sBlk.block_log
			i.start = header.start_block
			i.sparse = 0
			#i.block_ptr = block_ptr + 32 #sizeof(*inode)
			i.xattr = SQUASHFS_INVALID_XATTR
		elif header.inode_type==SQUASHFS_LREG_TYPE: 
			i.block_ptr = header.lreg_header(self.inode_table,block_ptr)
			i.data = header.file_size
			if header.fragment == SQUASHFS_INVALID_FRAG:
				i.frag_bytes = 0
			else:
				i.frag_bytes = header.file_size % self.sBlk.block_size
			i.fragment = header.fragment
			i.offset = header.offset
			if header.fragment == SQUASHFS_INVALID_FRAG:
				i.blocks = (header.file_size + self.sBlk.block_size - 1) >> self.sBlk.block_log
			else:
				i.blocks = header.file_size >> self.sBlk.block_log
			i.start = header.start_block
			i.sparse = header.sparse != 0
			#i.block_ptr = block_ptr + 60#sizeof(*inode)
			i.xattr = header.xattr
		elif header.inode_type==SQUASHFS_SYMLINK_TYPE or header.inode_type==SQUASHFS_LSYMLINK_TYPE: 
			header.symlink_header(self.inode_table,block_ptr)
			i.symlink = self.inode_table[block_ptr+24:block_ptr+24+header.symlink_size+1]
			i.symlink[header.symlink_size] = '\0'
			i.data = header.symlink_size
			if header.inode_type == SQUASHFS_LSYMLINK_TYPE:
				i.xattr = self.makeBufInteger(self.inode_table,block_ptr + 24 + header.symlink_size, 4)
			else:
				i.xattr = SQUASHFS_INVALID_XATTR
		elif header.inode_type==SQUASHFS_BLKDEV_TYPE or header.inode_type==SQUASHFS_CHRDEV_TYPE: 
			header.dev_header(self.inode_table,block_ptr)
			i.data = header.rdev
			i.xattr = SQUASHFS_INVALID_XATTR
		elif header.inode_type==SQUASHFS_LBLKDEV_TYPE or header.inode_type==SQUASHFS_LCHRDEV_TYPE: 
			header.ldev_header(self.inode_table,block_ptr)
			i.data = header.rdev
			i.xattr = header.xattr
		elif header.inode_type==SQUASHFS_FIFO_TYPE or header.inode_type==SQUASHFS_SOCKET_TYPE:
			i.data = 0
			i.xattr = SQUASHFS_INVALID_XATTR
		elif header.inode_type==SQUASHFS_LFIFO_TYPE or header.inode_type==SQUASHFS_LSOCKET_TYPE: 
			header.lipc_header(self.inode_table,block_ptr)
			i.data = 0
			i.xattr = header.xattr
		else:
			raise RuntimeError("Unknown inode type %d in read_inode!\n" % header.inode_type)
		return i

	def uncompress_directory_table(self,myfile,start,end):
		size  = 0 
		while start < end :
			self.directory_table_hash[start]=len(self.directory_table)
			block,start,byte_count = self.read_block(myfile, start)
			self.directory_table += block

	def squashfs_opendir(self,block_start,offset, s_file):
		i = self.read_inode(block_start, offset)
		start = self.sBlk.directory_table_start + i.start
		bytes = self.directory_table_hash[ start ]
		bytes += i.offset
		size = i.data + bytes - 3
		self.inode_to_file[i.inode_number] = s_file
		s_file.inode = i
		mydir = _Dir()
		mydir.dir_count = 0
		mydir.cur_entry = 0
		mydir.mode  = i.mode
		mydir.uid   = i.uid
		mydir.guid  = i.gid
		mydir.mtime = i.time
		mydir.xattr = i.xattr
		mydir.dirs  = []
		dirh = _Dir_header()
		while bytes < size :
			dirh.fill(self.directory_table,bytes)
			dir_count = dirh.count + 1
			bytes+=12
			while dir_count!=0 :
				dire = _Dir_entry()	
				dir_count-=1
				dire.fill(self.directory_table , bytes )
				bytes += 8
				dire.name= self.directory_table[ bytes:bytes+dire.size + 1]
				dire.s_file = SquashedFile(dire.name, s_file)
				s_file.children.append(dire.s_file)
				dire.parent = mydir
				dire.start_block = dirh.start_block
				mydir.dirs.append(dire)
				mydir.dir_count += 1
				bytes += dire.size + 1
		return (mydir,i)

	def read_uids_guids(self,myfile):
		indexes = SQUASHFS_ID_BLOCKS(self.sBlk.no_ids)
		id_index_table = [ None for i in range(0,indexes) ]
		self.id_table = [ None for i in range(0,self.sBlk.no_ids) ]
		myfile.seek(self.offset + self.sBlk.id_table_start,0)
		for  i in range(0,indexes):
			id_index_table[i] = self.makeInteger(myfile,SQUASHFS_ID_BLOCK_BYTES(1))
		for i in range(0,indexes) :
			myfile.seek(self.offset + id_index_table[i])
			block,next,bytes = self.read_block(myfile, id_index_table[i])
			offset = 0
			index = i * (SQUASHFS_METADATA_SIZE // 4)
			while offset<len(block):
				self.id_table[index], offset = self.autoMakeBufInteger(block,offset,4)
				index+=1

	def read_xattrs_from_disk(self,myfile):
		id_table = _Xattr_table()
		if self.sBlk.xattr_id_table_start == SQUASHFS_INVALID_BLK:
			return SQUASHFS_INVALID_BLK
		myfile.seek(self.offset + self.sBlk.xattr_id_table_start)
		id_table.read(myfile)
		ids = id_table.xattr_ids
		xattr_table_start = id_table.xattr_table_start
		index_bytes = SQUASHFS_XATTR_BLOCK_BYTES(ids)
		indexes = SQUASHFS_XATTR_BLOCKS(ids)
		index = []
		for r in range(0,ids):
			index.append( self.makeInteger(myfile,SQUASHFS_XATTR_BLOCK_BYTES(1)) )
		bytes = SQUASHFS_XATTR_BYTES(ids)
		xattr_ids = {}
		for i in range(0,indexes):
			block,next,byte_count = self.read_block(myfile,index[i])
			cur_idx = (i * SQUASHFS_METADATA_SIZE)/16
			ofs = 0
			while ofs<len(block):
				xattr_id = _Xattr_id()
				xattr_id.fill(block,ofs)
				xattr_ids[cur_idx]=xattr_id
				cur_idx+=1
				ofs+=16
		start = xattr_table_start
		end = index[0]
		xattr_values = {}
		i = 0
		while start<end:
			self.hash_table[start]= (i * SQUASHFS_METADATA_SIZE)
			block,start,byte_count = self.read_block(myfile,start)
			for i in range(len(block),SQUASHFS_METADATA_SIZE):
				block+=b'\x00'
			self.xattrs += block	
			i+=1
		return ids
		
	def pre_scan(self,parent_name,start_block,offset, parent):
		mydir,i = self.squashfs_opendir(start_block, offset, parent)
		while mydir.cur_entry < mydir.dir_count :
			dir_entry = mydir.dirs[mydir.cur_entry]
			name        = dir_entry.name
			start_block = dir_entry.start_block
			offset      = dir_entry.offset
			objtype     = dir_entry.type
			parent      = dir_entry.s_file
			mydir.cur_entry += 1
			pathname = str2byt(parent_name + '/') + name
			if objtype == SQUASHFS_DIR_TYPE :
				self.pre_scan(parent_name, start_block, offset, parent)
			else:
				if objtype == SQUASHFS_FILE_TYPE or objtype == SQUASHFS_LREG_TYPE :
					i = self.read_inode(start_block, offset)
					if self.created_inode[i.inode_number - 1] == None :
						self.created_inode[i.inode_number - 1] = i
						self.total_blocks += (i.data +(self.block_size-1)) >> self.block_log
					self.total_files +=1
				self.total_inodes +=1
				self.inode_to_file[i.inode_number] = dir_entry.s_file
				dir_entry.s_file.inode = i
		return mydir


if __name__=="__main__":
	import sys
	image = SquashFsImage(sys.argv[1])
	if len(sys.argv)>1 :
		for i in range(2,len(sys.argv)):
			sqashed_filename = sys.argv[i]
			squashed_file = image.root.select(sqashed_filename)
			print("--------------%-50.50s --------------" % sqashed_filename)
			if squashed_file==None:
				print("NOT FOUND")
			elif squashed_file.isFolder():
				print("FOLDER " + squashed_file.getPath())
				for child in squashed_file.children:
					if child.isFolder():
						print("\t%-20s <dir>" % child.name)
					else:
						print("\t%-20s %s" % (child.name,child.inode.data))
			else:  
				print(squashed_file.getContent())
	else:
		for i in image.root.findAll():
			nodetype = "FILE  "
			if i.isFolder():
				nodetype = "FOLDER"
			print(nodetype + ' ' + i.getPath() + " inode=" + i.inode.inode_number + " (" + image.read_block_list(i.inode) + " + " + i.inode.offset + ")")
			
		for i in image.root.findAll() :
			if i.name.endswith(".ini") :
				content = i.getContent()
				print("==============%-50.50s (%8d)==============" % (i.getPath(), len(content)))
				print(content)
			elif i.name.endswith(".so") :
				content = i.getContent()
				print("++++++++++++++%-50.50s (%8d)++++++++++++++" % (i.getPath(), len(content)))
				oname = i.name+"_saved_"+str(i.inode.inode_number)
				print("written %s from %s %d" % (oname, i.name, len(content)))
				of = file( oname , "wb" )
				of.write( content )
				of.close()
		image.close()

