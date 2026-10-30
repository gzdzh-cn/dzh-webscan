import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import 'element-plus/es/components/alert/style/css'
import 'element-plus/es/components/message/style/css'
import 'element-plus/es/components/button/style/css'
import 'element-plus/es/components/card/style/css'
import 'element-plus/es/components/dialog/style/css'
import 'element-plus/es/components/form/style/css'
import 'element-plus/es/components/form-item/style/css'
import 'element-plus/es/components/input/style/css'
import 'element-plus/es/components/input-number/style/css'
import 'element-plus/es/components/radio-group/style/css'
import 'element-plus/es/components/radio-button/style/css'
import 'element-plus/es/components/popconfirm/style/css'
import 'element-plus/es/components/select/style/css'
import 'element-plus/es/components/option/style/css'
import 'element-plus/es/components/pagination/style/css'
import 'element-plus/es/components/switch/style/css'
import 'element-plus/es/components/table/style/css'
import 'element-plus/es/components/table-column/style/css'
import 'element-plus/es/components/tag/style/css'
import 'element-plus/es/components/empty/style/css'
import 'element-plus/es/components/icon/style/css'
import 'element-plus/es/components/checkbox/style/css'
import 'element-plus/es/components/date-picker/style/css'
import 'element-plus/es/components/loading/style/css'
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
