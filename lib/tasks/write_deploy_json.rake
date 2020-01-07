namespace :login do
  desc 'generate a generic deploy.json file'
  task :deploy_json do
    puts 'Writing deploy.json'
    data = {
      env: ENV['environment'] || 'unkown',
      branch: `git branch --no-color 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/\1/'`.chomp[2..-1],
      user: 'n/a',
      git_sha: `git rev-parse HEAD`.chomp,
      git_date: Time.at(`git show -s --format=%ct HEAD`.chomp.to_i).iso8601,
      cloud_gov_deploy_timestamp: DateTime.now.strftime('%Y%m%d%H%M%S'),
      fqdn: 'n/a',
      instance_id: 'n/a',
    }

    # set deprecated attribute names
    data[:sha] = data[:git_sha]
    data[:timestamp] = data[:cloud_gov_deploy_timestamp]

    File.open('public/api/deploy.json', 'w') do |f|
      f.write(JSON.generate(data))
    end
  end
end
