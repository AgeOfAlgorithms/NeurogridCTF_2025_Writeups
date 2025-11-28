import { BrowserRouter as Router, Routes, Route } from "react-router";
import { useUsername } from "@/react-app/hooks/useUsername";
import Navbar from "@/react-app/components/Navbar";
import EnterName from "@/react-app/pages/EnterName";
import Marketplace from "@/react-app/pages/Marketplace";
import Orders from "@/react-app/pages/Orders";
import ListingDetail from "@/react-app/pages/ListingDetail";

export default function App() {
  const { username, saveUsername, clearUsername } = useUsername();

  if (!username) {
    return <EnterName onNameSubmit={saveUsername} />;
  }

  return (
    <Router>
      <div className="min-h-screen bg-transparent">
        <Navbar username={username} onLogout={clearUsername} />
        <Routes>
          <Route path="/" element={<Marketplace username={username} />} />
          <Route path="/orders" element={<Orders username={username} />} />
          <Route path="/listing/:id" element={<ListingDetail />} />
        </Routes>
      </div>
    </Router>
  );
}
