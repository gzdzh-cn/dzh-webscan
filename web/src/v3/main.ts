import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import 'element-plus/dist/index.css'
import { installElements } from '../elements'
import App from './App.vue'
import Servers from './Servers.vue'
import Deployments from './Deployments.vue'
import ConfigurationApplications from './ConfigurationApplications.vue'
import Events from './Events.vue'
import Alerts from './Alerts.vue'
import Websites from './Websites.vue'
import Settings from './Settings.vue'
import Backups from './Backups.vue'
import Dashboard from './Dashboard.vue'
import '../style.css'
import './style.css'

const router = createRouter({ history: createWebHistory(), routes: [
  { path: '/', component: Dashboard },
  { path: '/login', component: { render: () => null } },
  { path: '/servers/:id?', component: Servers },
  { path: '/deployments/:id?', component: Deployments },
  { path: '/configuration-applications/:id?', component: ConfigurationApplications },
  { path: '/events', component: Events },
  { path: '/alerts', component: Alerts },
  { path: '/settings', component: Settings },
  { path: '/backups', component: Backups },
  { path: '/config-backups', redirect: '/backups?tab=deployment' },
  { path: '/websites/:id?', component: Websites },
  { path: '/:pathMatch(.*)*', redirect: '/servers' },
] })
const app = createApp(App)
installElements(app)
app.use(router).mount('#app')
