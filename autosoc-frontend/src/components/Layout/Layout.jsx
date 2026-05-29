import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import TopNav from './TopNav';

export default function Layout() {
  return (
    <div className="min-h-screen">
      <Sidebar />
      <TopNav />
      <main className="ml-64 pt-16 p-6">
        <Outlet />
      </main>
    </div>
  );
}
