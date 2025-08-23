Vagrant.configure("2") do |config|
  host_os = RbConfig::CONFIG['host_os']
  host_cpu = RbConfig::CONFIG['host_cpu']

  if host_os =~ /darwin/ && host_cpu == "arm64"
    box = "bento/ubuntu-22.04"
  else
    box = "debian/bullseye64"
  end
  provider = "virtualbox"
  puts "🛠️  Vagrant is using provider: #{provider}, with box: #{box}"

  config.vm.box = box
  config.vm.provider provider do |vb|
    vb.name = "ft_traceroute"
    vb.memory = 1024
  end

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y \
      gcc \
      nmap \
      make \
      build-essential \
      libreadline-dev \
      libpcap-dev \
      pkg-config \
      traceroute \
      inetutils-ping \
      net-tools \
      procps
  SHELL
end

