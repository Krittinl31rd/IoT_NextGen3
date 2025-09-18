module.exports = {
  apps: [{
    name: 'nodeiotnextgen',
    script: 'npm',
    args: 'start', // Use '/c' to run npm via cmd
    watch: false,
    interpreter: 'none',        // Use "none" for npm commands
    env: {
      NODE_ENV: 'development', // Environment variables for development
    },
    env_production: {
      NODE_ENV: 'production',  // Environment variables for production
    },
  }],
  deploy: {
    production: {
      user: 'SSH_USERNAME',
      host: 'SSH_HOSTMACHINE',
      ref: 'origin/main',
      repo: 'GIT_REPOSITORY',
      path: 'DESTINATION_PATH',
      'pre-deploy-local': '',
      'post-deploy': 'npm install && pm2 reload ecosystem.config.js --env production',
      'pre-setup': ''
    }
  }
};
