require 'sinatra'
require 'haml'
require 'tokyocabinet'
include TokyoCabinet

Dir.glob('lib/*.rb') do |lib|
  require lib
end

module Syslog
  class Application < Sinatra::Base
    helpers do
      def ts_to_time(ts)
        e = ts.split('.');
        Time.at(e[0].to_i, e[1].to_i)
      end

      def facility(fac)
        case fac.to_i
          when 0: 'kernel'
          when 1: 'user'
          when 2: 'mail'
          when 3: 'system'
          when 4: 'auth'
          when 5: 'syslog'
          when 6: 'lp'
          when 7: 'news'
          when 8: 'uucp'
          when 9: 'cron'
          when 10: 'security'
          when 11: 'ftp'
          when 12: 'ntp'
          when 13: 'audit'
          when 14: 'alert'
          when 15: 'clock'
          when 16: 'local0'
          when 17: 'local1'
          when 18: 'local2'
          when 19: 'local3'
          when 20: 'local4'
          when 21: 'local5'
          when 22: 'local6'
          when 23: 'local7'
          else
            "unknown (#{fac})"
        end
      end

      def severity(sev)
        case sev.to_i
          when 0: 'emergency'
          when 1: 'alert'
          when 2: 'critical'
          when 3: 'error'
          when 4: 'warning'
          when 5: 'notice'
          when 6: 'info'
          when 7: 'debug'
          else
            "unknown (#{sev})"
        end
      end

      def header()
        haml :header, :layout => false
      end

      def footer()
        haml :footer, :layout => false
      end
    end

    def open_db()
      db = TDB::new()
      if !db.open('/home/oogali/code/libevent/syslog.tct', TDB::OREADER | TDB::ONOLCK) then
        halt 500, 'could not open database: ' + db.errmsg(db.ecode)
      end

      db
    end

    def get_msg(msgid)
      if msgid.nil? then
        nil
      end

      db = open_db()
      l = db.get(msgid)
      db.close()

      if l.nil?
        nil
      else
        Log.new(msgid, l)
      end
    end

    def find_msg(needle)
      results = Array.new

      if needle.nil? or needle.empty? then
        nil?
      end

      db = open_db()
      q = TDBQRY::new(db)
      q.addcond('msg', TDBQRY::QCSTRINC, needle)
      q.setorder('ts', TDBQRY::QONUMDESC)

      keys = q.search()
      keys.each do |key|
        results.push Log.new(key, db.get(key))
      end

      db.close()
      results
    end

    get '/' do
      haml :index
    end

    get '/styles/all.css' do
      content_type 'text/css', :charset => 'utf-8'
      expires -2592000
      sass :all
    end

    get '/get/*' do
      @msgid = params['splat'][0].to_i
      @log = get_msg(@msgid)
      haml :oneshot
    end

    def do_search(needle)
      @logs = find_msg(needle)

      haml :search
    end

    get '/search/*' do
      do_search(params['splat'][0])
    end

    post '/search' do
      do_search(params[:search])
    end
  end
end
