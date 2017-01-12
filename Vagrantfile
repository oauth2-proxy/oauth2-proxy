# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.box = "minimal/xenial64"

  config.vm.network "forwarded_port", guest: 8081, host: 8081
  config.vm.network "forwarded_port", guest: 8080, host: 8080

  config.vm.synced_folder "../../../", "/home/vagrant/go/src/"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "1024"
    vb.customize ["modifyvm", :id, "--cableconnected1", "on"]
  end

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install software-properties-common
    add-apt-repository ppa:ubuntu-lxc/lxd-stable
    apt-get update
    apt-get install -y python golang
  SHELL

  config.vm.provision "shell", inline: <<-SHELL
    echo 'export GOPATH=$HOME/go' > /etc/profile.d/gopath.sh
  SHELL
end
