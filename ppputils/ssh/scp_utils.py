from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient


def scp_upload(host, port, username, password, local_path, remote_path):
    """
    上传文件到远程服务器
    """
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(host, port=port, username=username, password=password)

    with SCPClient(ssh.get_transport()) as scp:
        scp.put(local_path, remote_path)  # 上传
    ssh.close()
    print(f"上传完成: {local_path} -> {username}@{host}:{remote_path}")


def scp_download(host, port, username, password, remote_path, local_path):
    """
    从远程服务器下载文件
    """
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(host, port=port, username=username, password=password)

    with SCPClient(ssh.get_transport()) as scp:
        scp.get(remote_path, local_path)  # 下载
    ssh.close()
    print(f"下载完成: {username}@{host}:{remote_path} -> {local_path}")
