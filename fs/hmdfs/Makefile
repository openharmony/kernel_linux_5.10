obj-$(CONFIG_HMDFS_FS) += hmdfs.o
ccflags-y += -I$(src)

hmdfs-y := main.o super.o inode.o dentry.o inode_root.o file_merge.o
hmdfs-y += hmdfs_client.o hmdfs_server.o inode_local.o inode_remote.o
hmdfs-y += inode_merge.o hmdfs_dentryfile.o file_root.o file_remote.o
hmdfs-y += file_local.o client_writeback.o server_writeback.o stash.o
hmdfs-y += hmdfs_share.o

hmdfs-y += file_cloud.o inode_cloud.o
hmdfs-y += comm/device_node.o comm/message_verify.o comm/node_cb.o
hmdfs-y += comm/connection.o comm/socket_adapter.o comm/transport.o

hmdfs-$(CONFIG_HMDFS_FS_ENCRYPTION) += comm/crypto.o
hmdfs-$(CONFIG_HMDFS_FS_PERMISSION) += authority/authentication.o
hmdfs-$(CONFIG_HMDFS_FS_PERMISSION) += authority/config.o
