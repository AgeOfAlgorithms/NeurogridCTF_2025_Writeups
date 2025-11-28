import { Zap } from 'lucide-react'

export default function Home() {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen">
      <div className="animate-spin">
        <Zap className="w-10 h-10 text-purple-400" />
      </div>
    </div>
  );
}
