import type { Metadata } from "next";
import { toolMetadata } from "@/lib/tools/registry";
import View from "./View";

export const metadata: Metadata = toolMetadata("jwt-inspector");

export default function Page() {
  return <View />;
}
