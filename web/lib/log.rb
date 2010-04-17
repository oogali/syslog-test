class Log
  attr_accessor :msgid, :ts, :src, :facility, :severity, :msg

  def initialize(msgid, dblog)
    @msgid = msgid
    @ts = dblog['ts']
    @src = dblog['src']
    @facility = dblog['facility']
    @severity = dblog['priority']
    @msg = dblog['msg']
  end

  def self.find_id(msgid)
    found = nil
    ObjectSpace.each_object(Log) { |o|
      found = o if o.msgid == msgid
    }
    found
  end

  def self.find_msg(needle)
    found = nil
    msgs = Array.new
    ObjectSpace.each_object(Log) { |o|
      found = true
      msgs.push o
    }

    if !found.nil? then
      msgs
    else
      found
    end
  end
end
